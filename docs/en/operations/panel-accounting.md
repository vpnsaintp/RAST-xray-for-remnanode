# Panel accounting and access feed

The entry configuration may assign a positive numeric `panelUserId` to each
VLESS user. This ID is independent of the UUID credential and optional `label`.
For a panel-managed entry, `users: []` is valid only when
`reality.sharedShortIds` is configured. It starts with no authorized clients
and accepts identities added by the node adapter after startup.
In a Handoff topology the entry retains the client's online IP and emits the
destination event; the landing configuration maps the same UUID to the same
ID in `accountingUsers` and counts application bytes after the transfer.
The panel must combine the two nodes' usage without counting the entry's
Handoff bytes twice.

Set `RUST_REALITY_MANAGEMENT_SOCKET` to an absolute path in a private directory
owned by the service account. The process binds a mode `0600` Unix socket.
Each connection receives one newline-terminated JSON object with `version`,
`bootId`, `generation`, `activePanelIds` and `users`. Each user has a decimal
`label` equal to its panel ID, cumulative `uplink` and `downlink` application
bytes, and `onlineIps`. The feed is read-only and has no network listener.
The process also binds a mode `0600` Unix socket at the same path plus
`.control`. A local panel adapter can send one bounded JSON line such as
`{"command":"dropUsers","userIds":[123]}` to terminate that user's existing
sessions. Removed or rotated UUIDs are also retired when a new configuration
generation is published. The read-only accounting socket accepts no commands.

The consumer must keep a durable cursor for each `bootId` and submit only
positive deltas. The RemnaNode adapter advances its cursor when it prepares a
reset response; the panel API has no separate acknowledgement. A lost response
can therefore miss that interval, and a core crash can lose bytes accumulated
after the last poll. The consumer should flag a changed `bootId` instead of
silently reporting zero usage. A config reload
increments `generation`; `activePanelIds` lets the consumer check that an
identity update actually reached the serving core.

An entry `log` at `info` level emits `access_decision` JSON records with
`panel_user_id`, `source_ip`, `network`, `destination` and `outbound`. This is
destination evidence for an operator's torrent activity monitor. It does not
by itself prove BitTorrent protocol use; the monitor must retain its separate
confirmation criteria. Keep log files private and bounded with the log sink's
rotation settings.
