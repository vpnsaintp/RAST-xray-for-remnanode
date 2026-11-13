//! Client verification of the REALITY server flight certificate binding.
//!
//! The server forges a fixed 178-byte self-signed Ed25519 certificate and writes
//! the per-process Ed25519 public key at DER offset 72 plus
//! `HMAC-SHA512(auth_key, that public key)` at DER offset 114. The client checks
//! that binding and the matching `CertificateVerify` signature so a cover
//! fallback cannot be mistaken for an authenticated peer.

use std::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
use subtle::ConstantTimeEq;

use super::AuthKey;

/// Handshake type byte for `EncryptedExtensions`.
pub(crate) const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 8;
/// Handshake type byte for `Certificate`.
pub(crate) const HANDSHAKE_CERTIFICATE: u8 = 11;
/// Handshake type byte for `CertificateVerify`.
pub(crate) const HANDSHAKE_CERTIFICATE_VERIFY: u8 = 15;
/// Handshake type byte for `Finished`.
pub(crate) const HANDSHAKE_FINISHED: u8 = 20;
/// The `Ed25519` signature scheme the server always selects.
const ED25519_SCHEME: u16 = 0x0807;
/// The TLS 1.3 certificate-verify label, used verbatim in the signed structure.
const CERTIFICATE_VERIFY_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";
/// Zero-padded hash-block-sized prefix length in that structure.
const CERTIFICATE_VERIFY_PAD_LEN: usize = 64;
/// The only extension the server's `EncryptedExtensions` may carry.
const EXTENSION_ALPN: u16 = 0x0010;
/// DER offset of the embedded Ed25519 public key.
const PUBLIC_KEY_OFFSET: usize = 72;
/// DER offset of the HMAC binding that stands in for the certificate signature.
const BINDING_OFFSET: usize = 114;
/// Length of the embedded public key.
const PUBLIC_KEY_LEN: usize = 32;
/// Length of the HMAC-SHA512 binding.
const BINDING_LEN: usize = 64;
/// The only certificate length the server can produce, since its template is a
/// fixed-size array patched in place rather than re-encoded.
const CERTIFICATE_DER_LEN: usize = BINDING_OFFSET + BINDING_LEN;
/// Length of an Ed25519 signature.
const ED25519_SIGNATURE_LEN: usize = 64;

/// v2.0.1's unmodified certificate template, copied from
/// `tls13/messages.rs:27-40`, so the tests forge the bytes the server sends and
/// not a shape that happens to suit the verifier.
#[cfg(test)]
pub(crate) const CERTIFICATE_TEMPLATE: [u8; CERTIFICATE_DER_LEN] = [
    0x30, 0x81, 0xaf, 0x30, 0x63, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x30, 0x00, 0x30, 0x22, 0x18, 0x0f, 0x30, 0x30, 0x30, 0x31, 0x30, 0x31,
    0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x30, 0x30, 0x30, 0x31, 0x30,
    0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x00, 0x30, 0x2a, 0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0x21, 0x52, 0xf8, 0xd1, 0x9b, 0x79, 0x1d, 0x24,
    0x45, 0x32, 0x42, 0xe1, 0x5f, 0x2e, 0xab, 0x6c, 0xb7, 0xcf, 0xfa, 0x7b, 0x6a, 0x5e, 0xd3, 0x00,
    0x97, 0x96, 0x0e, 0x06, 0x98, 0x81, 0xdb, 0x12, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03,
    0x41, 0x00, 0x52, 0xc8, 0x4d, 0x3d, 0xc8, 0xf1, 0x23, 0xbb, 0x88, 0x9b, 0x05, 0x98, 0xfe, 0x11,
    0x4d, 0x36, 0xd0, 0x59, 0x9f, 0x20, 0xf3, 0xd0, 0x91, 0xb1, 0x28, 0x4a, 0x84, 0x5a, 0x5d, 0x81,
    0x8c, 0x9f, 0x85, 0x1f, 0x44, 0x10, 0x08, 0xd2, 0xf8, 0x4a, 0x5f, 0x9e, 0xbc, 0xcc, 0x8e, 0x82,
    0x43, 0xd9, 0x33, 0x2b, 0x16, 0x0c, 0x03, 0x8e, 0x52, 0xba, 0x8a, 0x2c, 0xe6, 0xf7, 0x00, 0x60,
    0x36, 0x04,
];

/// A server flight message was not what the configured node should have sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateError {
    /// A message is shorter than its own declared lengths.
    Truncated,
    /// A fixed field or vector frame is not exact.
    Malformed(&'static str),
    /// The certificate's binding is not an HMAC of the authenticated key.
    ///
    /// This is the signal that the peer is not the configured REALITY node: a
    /// wrong public key, a wrong short ID, or a server that fell back to its
    /// cover target and presented a real PKI certificate instead.
    Binding,
    /// `CertificateVerify` is not a valid signature by the embedded key.
    Signature,
    /// The server's `Finished` verify data did not match our computation.
    Finished,
}

impl fmt::Display for CertificateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("truncated handshake message"),
            Self::Malformed(field) => write!(formatter, "malformed handshake message {field}"),
            Self::Binding => formatter.write_str("certificate is not bound to our REALITY key"),
            Self::Signature => formatter.write_str("certificate signature did not verify"),
            Self::Finished => formatter.write_str("server Finished verify data did not match"),
        }
    }
}

impl std::error::Error for CertificateError {}

/// Bounded cursor over one handshake message body.
struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    const fn remaining(&self) -> usize {
        self.data.len() - self.position
    }

    const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn subreader(&mut self, len: usize) -> Option<Reader<'a>> {
        self.read(len).map(Reader::new)
    }

    fn read(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.position.checked_add(len)?;
        let bytes = self.data.get(self.position..end)?;
        self.position = end;
        Some(bytes)
    }

    fn skip(&mut self, len: usize) -> Option<()> {
        self.read(len).map(|_| ())
    }

    fn read_u8(&mut self) -> Option<u8> {
        Some(*self.read(1)?.first()?)
    }

    fn read_u16(&mut self) -> Option<u16> {
        let bytes = self.read(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u24(&mut self) -> Option<usize> {
        let bytes = self.read(3)?;
        Some(usize::from(bytes[0]) << 16 | usize::from(bytes[1]) << 8 | usize::from(bytes[2]))
    }
}

/// Compares the certificate binding without a timing signal.
fn binding_matches(expected: &[u8; 64], observed: &[u8]) -> bool {
    observed.len() == expected.len() && bool::from(expected.ct_eq(observed))
}

/// Returns the body of one expected handshake message.
///
/// The declared length must consume the message exactly, so a truncated or
/// over-long frame cannot smuggle trailing bytes into the transcript.
fn body(expected_type: u8, message: &[u8]) -> Result<&[u8], CertificateError> {
    let mut reader = Reader::new(message);
    if reader.read_u8().ok_or(CertificateError::Truncated)? != expected_type {
        return Err(CertificateError::Malformed("handshake type"));
    }
    let declared = reader.read_u24().ok_or(CertificateError::Truncated)?;
    if declared != reader.remaining() {
        return Err(CertificateError::Malformed("declared length"));
    }
    reader
        .read(declared)
        .ok_or(CertificateError::Malformed("declared length"))
}

/// Narrows a cursor to the next 16-bit-prefixed vector.
fn read_vector<'reader>(
    reader: &mut Reader<'reader>,
    field: &'static str,
) -> Result<Reader<'reader>, CertificateError> {
    let length = usize::from(reader.read_u16().ok_or(CertificateError::Truncated)?);
    reader
        .subreader(length)
        .ok_or(CertificateError::Malformed(field))
}

/// Narrows a cursor to the next 24-bit-prefixed vector.
fn read_vector_u24<'reader>(
    reader: &mut Reader<'reader>,
    field: &'static str,
) -> Result<Reader<'reader>, CertificateError> {
    let length = reader.read_u24().ok_or(CertificateError::Truncated)?;
    reader
        .subreader(length)
        .ok_or(CertificateError::Malformed(field))
}

/// Extracts the ALPN the server selected from its `EncryptedExtensions`.
///
/// The server may claim no protocol at all: when its flight plan comes from a
/// cover that negotiated none, the generated `EncryptedExtensions` is the minimal
/// empty form (`tls13/messages.rs:171-176`). A claimed protocol must be one we
/// actually offered, or the negotiation is a lie.
///
/// # Errors
///
/// Returns [`CertificateError`] for malformed frames or an unoffered protocol.
pub fn parse_encrypted_extensions(
    message: &[u8],
    offered: &[&[u8]],
) -> Result<Option<Vec<u8>>, CertificateError> {
    let body = body(HANDSHAKE_ENCRYPTED_EXTENSIONS, message)?;
    let mut reader = Reader::new(body);
    let mut extensions = read_vector(&mut reader, "extensions trailing bytes")?;
    if !reader.is_empty() {
        return Err(CertificateError::Malformed("extensions trailing bytes"));
    }
    let mut seen: Vec<u16> = Vec::new();
    let mut selected: Option<Vec<u8>> = None;
    while !extensions.is_empty() {
        let extension_type = extensions.read_u16().ok_or(CertificateError::Truncated)?;
        if seen.contains(&extension_type) {
            return Err(CertificateError::Malformed("duplicate extension"));
        }
        seen.push(extension_type);
        let mut extension = read_vector(&mut extensions, "extension length")?;
        if extension_type == EXTENSION_ALPN {
            let mut protocols = read_vector(&mut extension, "alpn list")?;
            let mut claimed: Option<Vec<u8>> = None;
            while !protocols.is_empty() {
                let length = usize::from(protocols.read_u8().ok_or(CertificateError::Truncated)?);
                let candidate = protocols
                    .read(length)
                    .ok_or(CertificateError::Truncated)?
                    .to_vec();
                if candidate.is_empty() || claimed.is_some() {
                    return Err(CertificateError::Malformed("alpn protocol"));
                }
                claimed = Some(candidate);
            }
            let claimed = claimed.ok_or(CertificateError::Malformed("empty alpn"))?;
            if !offered.iter().any(|protocol| *protocol == claimed) {
                return Err(CertificateError::Malformed("unoffered alpn"));
            }
            if selected.is_some() {
                return Err(CertificateError::Malformed("duplicate alpn"));
            }
            selected = Some(claimed);
        }
        if !extension.is_empty() {
            return Err(CertificateError::Malformed("extension length"));
        }
    }
    Ok(selected)
}

/// Verifies the forged certificate and returns the Ed25519 key it embeds.
///
/// # Errors
///
/// Returns [`CertificateError::Binding`] when the embedded HMAC does not match
/// `auth_key`, which is how a cover fallback is detected.
pub fn verify_server_certificate(
    message: &[u8],
    auth_key: &AuthKey,
) -> Result<[u8; PUBLIC_KEY_LEN], CertificateError> {
    let body = body(HANDSHAKE_CERTIFICATE, message)?;
    let mut reader = Reader::new(body);
    if reader.read_u8().ok_or(CertificateError::Truncated)? != 0 {
        return Err(CertificateError::Malformed("certificate context"));
    }
    let certificate = read_certificate_entry(&mut reader)?;
    if !reader.is_empty() {
        return Err(CertificateError::Malformed("certificate trailing bytes"));
    }
    if certificate.len() != CERTIFICATE_DER_LEN {
        return Err(CertificateError::Binding);
    }
    let embedded = certificate
        .get(PUBLIC_KEY_OFFSET..PUBLIC_KEY_OFFSET + PUBLIC_KEY_LEN)
        .ok_or(CertificateError::Binding)?
        .try_into()
        .map_err(|_| CertificateError::Binding)?;
    let observed = certificate
        .get(BINDING_OFFSET..)
        .ok_or(CertificateError::Binding)?;
    if !binding_matches(&expected_binding(auth_key, &embedded), observed) {
        return Err(CertificateError::Binding);
    }
    Ok(embedded)
}

/// Verifies the `CertificateVerify` message against the embedded key.
///
/// The signed structure is TLS 1.3's: 64 bytes of hash-block padding, the server
/// label, a zero separator, and the transcript hash through the certificate
/// (`tls13/messages.rs:117-150`). Verification is strict, so a malleated
/// signature does not pass.
///
/// # Errors
///
/// Returns [`CertificateError::Signature`] for a wrong scheme, size, or key.
pub(crate) fn verify_certificate_signature(
    message: &[u8],
    public_key: &[u8; PUBLIC_KEY_LEN],
    transcript_hash: &[u8],
) -> Result<(), CertificateError> {
    if transcript_hash.len() != 32 && transcript_hash.len() != 48 {
        return Err(CertificateError::Malformed("transcript hash"));
    }
    let body = body(HANDSHAKE_CERTIFICATE_VERIFY, message)?;
    let mut reader = Reader::new(body);
    if reader.read_u16().ok_or(CertificateError::Truncated)? != ED25519_SCHEME {
        return Err(CertificateError::Malformed("signature scheme"));
    }
    let mut signature = read_vector(&mut reader, "certificate verify trailing bytes")?;
    if !reader.is_empty() {
        return Err(CertificateError::Malformed(
            "certificate verify trailing bytes",
        ));
    }
    let remaining = signature.remaining();
    if remaining != ED25519_SIGNATURE_LEN {
        return Err(CertificateError::Signature);
    }
    let raw: [u8; ED25519_SIGNATURE_LEN] = signature
        .read(remaining)
        .ok_or(CertificateError::Signature)?
        .try_into()
        .map_err(|_| CertificateError::Signature)?;
    let verifying =
        VerifyingKey::from_bytes(public_key).map_err(|_| CertificateError::Signature)?;
    let mut signed = Vec::with_capacity(
        CERTIFICATE_VERIFY_PAD_LEN + CERTIFICATE_VERIFY_CONTEXT.len() + 1 + transcript_hash.len(),
    );
    signed.resize(CERTIFICATE_VERIFY_PAD_LEN, 0x20);
    signed.extend_from_slice(CERTIFICATE_VERIFY_CONTEXT);
    signed.push(0);
    signed.extend_from_slice(transcript_hash);
    verifying
        .verify_strict(&signed, &Signature::from_bytes(&raw))
        .map_err(|_| CertificateError::Signature)
}

/// Checks the server's `Finished` against our own computation.
///
/// # Errors
///
/// Returns [`CertificateError::Finished`] on any mismatch, compared without a
/// timing signal.
pub(crate) fn verify_finished(message: &[u8], expected: &[u8]) -> Result<(), CertificateError> {
    let body = body(HANDSHAKE_FINISHED, message)?;
    if body.len() != expected.len() {
        return Err(CertificateError::Finished);
    }
    if bool::from(body.ct_eq(expected)) {
        Ok(())
    } else {
        Err(CertificateError::Finished)
    }
}

/// `HMAC-SHA512(auth_key, public_key)`, the value the server writes at
/// [`BINDING_OFFSET`].
fn expected_binding(auth_key: &AuthKey, public_key: &[u8; PUBLIC_KEY_LEN]) -> [u8; BINDING_LEN] {
    let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(auth_key.as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(public_key);
    let digest = mac.finalize().into_bytes();
    let mut binding = [0_u8; BINDING_LEN];
    binding.copy_from_slice(&digest);
    binding
}

/// Reads the single certificate entry the server writes: a 24-bit frame whose
/// content is a 24-bit DER length, the DER, and a 16-bit extension length.
///
/// This is v2.0.1's own framing (`tls13/messages.rs:213-236`), which puts the
/// entry frame where RFC 8446 puts the list frame and carries no
/// `signature_scheme`. The flight is what the unmodified server produces, so it
/// is what a client must accept; nothing here is relaxed to accommodate it.
fn read_certificate_entry<'list>(
    reader: &mut Reader<'list>,
) -> Result<&'list [u8], CertificateError> {
    let mut entry = read_vector_u24(reader, "certificate entry length")?;
    let der_len = entry.read_u24().ok_or(CertificateError::Truncated)?;
    let certificate = entry
        .read(der_len)
        .ok_or(CertificateError::Malformed("certificate length"))?;
    let extensions = usize::from(entry.read_u16().ok_or(CertificateError::Truncated)?);
    entry
        .skip(extensions)
        .ok_or(CertificateError::Malformed("certificate extensions"))?;
    if !entry.is_empty() {
        return Err(CertificateError::Malformed(
            "certificate entry trailing bytes",
        ));
    }
    Ok(certificate)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    const RANDOM: [u8; 32] = [0x5a; 32];

    fn auth_key() -> AuthKey {
        AuthKey::derive(&[0x11; 32], &RANDOM).expect("derive")
    }

    fn message(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![kind];
        let length = u32::try_from(body.len()).expect("body");
        out.extend_from_slice(&length.to_be_bytes()[1..]);
        out.extend_from_slice(body);
        out
    }

    /// Rebuilds the server's certificate message from its own recipe, so the
    /// verifier is tested against bytes the server can actually produce.
    fn certificate_message(certificate_der: &[u8]) -> Vec<u8> {
        let entry_len = certificate_der.len() + 3 + 2;
        let body_len = entry_len + 1 + 3;
        let mut body = Vec::new();
        body.push(0);
        let entry = u32::try_from(entry_len).expect("entry");
        body.extend_from_slice(&entry.to_be_bytes()[1..]);
        let der_len = u32::try_from(certificate_der.len()).expect("der");
        body.extend_from_slice(&der_len.to_be_bytes()[1..]);
        body.extend_from_slice(certificate_der);
        body.extend_from_slice(&[0, 0]);
        assert_eq!(body_len, body.len());
        message(HANDSHAKE_CERTIFICATE, &body)
    }

    /// The server's fixed-size template with the binding patched in, following
    /// `tls13/messages.rs:91-110`.
    pub(crate) fn forged_certificate(
        auth_key: &AuthKey,
        public_key: &[u8; PUBLIC_KEY_LEN],
    ) -> Vec<u8> {
        let mut der = CERTIFICATE_TEMPLATE.to_vec();
        der[PUBLIC_KEY_OFFSET..PUBLIC_KEY_OFFSET + PUBLIC_KEY_LEN].copy_from_slice(public_key);
        der[BINDING_OFFSET..].copy_from_slice(&expected_binding(auth_key, public_key));
        der
    }

    fn signed_payload(transcript_hash: &[u8]) -> Vec<u8> {
        let mut signed = Vec::new();
        signed.resize(CERTIFICATE_VERIFY_PAD_LEN, 0x20);
        signed.extend_from_slice(CERTIFICATE_VERIFY_CONTEXT);
        signed.push(0);
        signed.extend_from_slice(transcript_hash);
        signed
    }

    fn certificate_verify(signature: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&ED25519_SCHEME.to_be_bytes());
        body.extend_from_slice(
            &u16::try_from(signature.len())
                .expect("signature")
                .to_be_bytes(),
        );
        body.extend_from_slice(signature);
        message(HANDSHAKE_CERTIFICATE_VERIFY, &body)
    }

    #[test]
    fn accepts_a_certificate_bound_to_the_auth_key() {
        let key = auth_key();
        let public = [0x42; 32];
        let verified = verify_server_certificate(
            &certificate_message(&forged_certificate(&key, &public)),
            &key,
        )
        .expect("verify");
        assert_eq!(public, verified);
    }

    #[test]
    fn rejects_a_certificate_bound_to_a_different_key() {
        let key = auth_key();
        let other = AuthKey::derive(&[0x22; 32], &RANDOM).expect("derive");
        let public = [0x42; 32];
        assert!(matches!(
            verify_server_certificate(
                &certificate_message(&forged_certificate(&other, &public)),
                &key
            ),
            Err(CertificateError::Binding)
        ));
    }

    #[test]
    fn rejects_a_real_pki_certificate() {
        let key = auth_key();
        // A cover target's certificate is longer than the fixed template.
        assert!(matches!(
            verify_server_certificate(&certificate_message(&vec![0x30; 800]), &key),
            Err(CertificateError::Binding)
        ));
    }

    #[test]
    fn rejects_a_message_with_no_certificate() {
        let key = auth_key();
        assert!(matches!(
            verify_server_certificate(&message(HANDSHAKE_CERTIFICATE, &[0, 0, 0, 0]), &key),
            Err(CertificateError::Truncated)
        ));
    }

    #[test]
    fn rejects_a_certificate_entry_with_extra_bytes() {
        let key = auth_key();
        let public = [0x42; 32];
        let der = forged_certificate(&key, &public);
        let mut body = Vec::new();
        body.push(0);
        let entry = u32::try_from(der.len() + 3 + 2 + 1).expect("entry");
        body.extend_from_slice(&entry.to_be_bytes()[1..]);
        let der_len = u32::try_from(der.len()).expect("der");
        body.extend_from_slice(&der_len.to_be_bytes()[1..]);
        body.extend_from_slice(&der);
        body.extend_from_slice(&[0, 0, 0x7f]);
        assert!(matches!(
            verify_server_certificate(&message(HANDSHAKE_CERTIFICATE, &body), &key),
            Err(CertificateError::Malformed(
                "certificate entry trailing bytes"
            ))
        ));
    }

    #[test]
    fn verifies_an_ed25519_signature_by_the_embedded_key() {
        let signing = SigningKey::from_bytes(&[0x07; 32]);
        let public = signing.verifying_key().to_bytes();
        let transcript = [0x33; 32];
        let signature = signing.sign(&signed_payload(&transcript)).to_bytes();
        verify_certificate_signature(&certificate_verify(&signature), &public, &transcript)
            .expect("verify");
    }

    #[test]
    fn rejects_a_signature_over_a_different_transcript() {
        let signing = SigningKey::from_bytes(&[0x07; 32]);
        let public = signing.verifying_key().to_bytes();
        let signature = signing.sign(&signed_payload(&[0x33; 32])).to_bytes();
        assert!(matches!(
            verify_certificate_signature(&certificate_verify(&signature), &public, &[0x34; 32]),
            Err(CertificateError::Signature)
        ));
    }

    #[test]
    fn rejects_a_foreign_signature_scheme() {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0403_u16.to_be_bytes());
        body.extend_from_slice(&[0, 64]);
        body.extend_from_slice(&[0_u8; 64]);
        assert!(matches!(
            verify_certificate_signature(
                &message(HANDSHAKE_CERTIFICATE_VERIFY, &body),
                &[0x42; 32],
                &[0x33; 32]
            ),
            Err(CertificateError::Malformed("signature scheme"))
        ));
    }

    #[test]
    fn accepts_only_an_offered_alpn() {
        let offered: &[&[u8]] = &[b"h2", b"http/1.1"];
        assert_eq!(
            Some(b"h2".to_vec()),
            parse_encrypted_extensions(&alpn_message(b"h2"), offered).expect("parse")
        );
        assert!(matches!(
            parse_encrypted_extensions(&alpn_message(b"srv"), offered),
            Err(CertificateError::Malformed("unoffered alpn"))
        ));
    }

    /// `EncryptedExtensions` claiming exactly one ALPN protocol.
    fn alpn_message(protocol: &[u8]) -> Vec<u8> {
        let mut inner = Vec::new();
        let list_len = u16::try_from(protocol.len() + 1).expect("list");
        inner.extend_from_slice(&list_len.to_be_bytes());
        let length = u8::try_from(protocol.len()).expect("protocol");
        inner.push(length);
        inner.extend_from_slice(protocol);
        let mut extension = Vec::new();
        extension.extend_from_slice(&EXTENSION_ALPN.to_be_bytes());
        extension.extend_from_slice(&u16::try_from(inner.len()).expect("extension").to_be_bytes());
        extension.extend_from_slice(&inner);
        let mut body = Vec::new();
        body.extend_from_slice(
            &u16::try_from(extension.len())
                .expect("extensions")
                .to_be_bytes(),
        );
        body.extend_from_slice(&extension);
        message(HANDSHAKE_ENCRYPTED_EXTENSIONS, &body)
    }

    #[test]
    fn accepts_an_empty_encrypted_extensions() {
        let built = message(HANDSHAKE_ENCRYPTED_EXTENSIONS, &[0, 0]);
        assert_eq!(
            None,
            parse_encrypted_extensions(&built, &[b"h2"]).expect("parse")
        );
    }

    #[test]
    fn finished_round_trips_and_rejects_a_tampered_digest() {
        let verify_data = [0x77; 32];
        let built = message(HANDSHAKE_FINISHED, &verify_data);
        verify_finished(&built, &verify_data).expect("verify");
        assert!(matches!(
            verify_finished(&built, &[0x76; 32]),
            Err(CertificateError::Finished)
        ));
    }

    #[test]
    fn rejects_a_message_whose_declared_length_lies() {
        let mut built = message(HANDSHAKE_CERTIFICATE, &[0, 0, 0, 0]);
        built[2] = 0xff;
        assert!(matches!(
            body(HANDSHAKE_CERTIFICATE, &built),
            Err(CertificateError::Malformed("declared length"))
        ));
    }
}
