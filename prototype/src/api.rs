use std::sync::Arc;

use anyhow::{Context, Result};
use prost::Message;
use tokio::net::UnixListener;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Request, Response, Status};

use crate::backend::Backend;
use crate::go_router::TORRENT_OUTBOUND;
use crate::state::{State, User as Client, Users, VISION, read_counter};

mod handler {
    tonic::include_proto!("xray.app.proxyman.command");
}

mod stats {
    tonic::include_proto!("xray.app.stats.command");
}

mod routing {
    tonic::include_proto!("xray.app.router.command");
}

use handler::{
    handler_service_server::{HandlerService, HandlerServiceServer},
    *,
};
use stats::{
    stats_service_server::{StatsService, StatsServiceServer},
    *,
};

#[derive(Clone)]
struct Api {
    state: Arc<State>,
    backend: Arc<Backend>,
    mutations: Arc<tokio::sync::Mutex<()>>,
}

impl Api {
    fn alter_shadowsocks(
        &self,
        users: &crate::shadowsocks::Users,
        operation: TypedMessage,
    ) -> Result<Response<AlterInboundResponse>, Status> {
        let mut users = users.write().unwrap();
        match operation.r#type.as_str() {
            "xray.app.proxyman.command.AddUserOperation" => {
                let user = decode::<AddUserOperation>(&operation.value)?
                    .user
                    .ok_or_else(|| Status::invalid_argument("user missing"))?;
                let account = user
                    .account
                    .ok_or_else(|| Status::invalid_argument("account missing"))?;
                if account.r#type != crate::shadowsocks::ACCOUNT_TYPE || user.level != 0 {
                    return Err(Status::unimplemented(
                        "unsupported Shadowsocks account settings",
                    ));
                }
                let client =
                    crate::shadowsocks::Client::from_account(user.email, decode(&account.value)?)
                        .map_err(|_| Status::invalid_argument("invalid Shadowsocks account"))?;
                if users
                    .values()
                    .any(|old| old.user.email == client.user.email && old.same_key(&client))
                {
                    return Ok(Response::new(AlterInboundResponse {}));
                }
                if users.contains_key(&client.id())
                    || users
                        .values()
                        .any(|old| old.user.email == client.user.email || old.same_key(&client))
                {
                    return Err(Status::already_exists("user already exists"));
                }
                users.insert(client.id(), client);
            }
            "xray.app.proxyman.command.RemoveUserOperation" => {
                let email = decode::<RemoveUserOperation>(&operation.value)?.email;
                let id = users
                    .values()
                    .find(|client| client.user.email == email)
                    .map(|client| client.id())
                    .ok_or_else(|| Status::not_found("user missing"))?;
                if let Some(client) = users.remove(&id) {
                    client.user.cancel();
                }
                self.state.stats.remove_online(&email);
            }
            _ => return Err(Status::unimplemented("unsupported inbound operation")),
        }
        Ok(Response::new(AlterInboundResponse {}))
    }

    async fn forward(&self, tag: &str, kind: &str, value: Vec<u8>) -> Result<(), Status> {
        if let Some(router) = self.backend.go() {
            handler::handler_service_client::HandlerServiceClient::new(router.channel.clone())
                .alter_inbound(AlterInboundRequest {
                    tag: tag.to_owned(),
                    operation: Some(TypedMessage {
                        r#type: kind.to_owned(),
                        value,
                    }),
                })
                .await
                .map_err(|status| {
                    Status::new(status.code(), "routing companion rejected inbound update")
                })?;
        }
        Ok(())
    }

    fn inbound(&self, tag: &str) -> Result<&Arc<Users>, Status> {
        self.state
            .inbounds
            .get(tag)
            .ok_or_else(|| Status::not_found("unknown inbound"))
    }
}

pub async fn serve(name: String, state: Arc<State>, backend: Arc<Backend>) -> Result<()> {
    let name = name
        .strip_prefix('@')
        .context("API listen must be an abstract Unix socket")?;
    let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
    let listener = std::os::unix::net::UnixListener::bind_addr(&address)?;
    listener.set_nonblocking(true)?;
    let api = Api {
        state,
        backend,
        mutations: Arc::new(tokio::sync::Mutex::new(())),
    };
    // Remnanode and the core run under the same UID. Abstract sockets have no
    // filesystem permissions, so reject other UIDs before starting gRPC.
    let uid = unsafe { libc::geteuid() };
    let incoming =
        UnixListenerStream::new(UnixListener::from_std(listener)?).filter_map(move |accepted| {
            match accepted {
                Ok(stream) if stream.peer_cred().is_ok_and(|peer| peer.uid() == uid) => {
                    Some(Ok(stream))
                }
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            }
        });
    tonic::transport::Server::builder()
        .add_service(HandlerServiceServer::new(api.clone()))
        .add_service(StatsServiceServer::new(api))
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}

use std::os::linux::net::SocketAddrExt;

#[tonic::async_trait]
impl HandlerService for Api {
    async fn remove_outbound(
        &self,
        request: Request<RemoveOutboundRequest>,
    ) -> Result<Response<RemoveOutboundResponse>, Status> {
        let request = request.into_inner();
        let _guard = self.mutations.lock().await;
        if let Backend::Native(router) = self.backend.as_ref() {
            if request.tag == TORRENT_OUTBOUND {
                router.disable_torrent();
                return Ok(Response::new(RemoveOutboundResponse {}));
            }
            return Err(Status::unimplemented(
                "native outbound removal is only supported for Torrent Blocker",
            ));
        }
        let router = self.backend.go().expect("Go backend");
        if request.tag == TORRENT_OUTBOUND {
            routing::routing_service_client::RoutingServiceClient::new(router.channel.clone())
                .remove_rule(routing::RemoveRuleRequest {
                    rule_tag: router.torrent_rule_tag.clone(),
                })
                .await
                .map_err(|status| {
                    Status::new(
                        status.code(),
                        "routing companion rejected Torrent Blocker rule removal",
                    )
                })?;
        }
        handler::handler_service_client::HandlerServiceClient::new(router.channel.clone())
            .remove_outbound(request)
            .await
            .map_err(|status| {
                Status::new(status.code(), "routing companion rejected outbound removal")
            })
    }

    async fn alter_inbound(
        &self,
        request: Request<AlterInboundRequest>,
    ) -> Result<Response<AlterInboundResponse>, Status> {
        let request = request.into_inner();
        let op = request
            .operation
            .ok_or_else(|| Status::invalid_argument("operation missing"))?;
        let _guard = self.mutations.lock().await;
        if let Some(users) = self.state.shadowsocks.get(&request.tag) {
            return self.alter_shadowsocks(users, op);
        }
        let users = self.inbound(&request.tag)?;
        match op.r#type.as_str() {
            "xray.app.proxyman.command.AddUserOperation" => {
                let mut user = decode::<AddUserOperation>(&op.value)?
                    .user
                    .ok_or_else(|| Status::invalid_argument("user missing"))?;
                let typed = user
                    .account
                    .as_mut()
                    .ok_or_else(|| Status::invalid_argument("account missing"))?;
                if typed.r#type != "xray.proxy.vless.Account" {
                    return Err(Status::unimplemented("only VLESS accounts are supported"));
                }
                let mut account = decode::<Account>(&typed.value)?;
                if !account.reverse.is_empty()
                    || !matches!(account.encryption.as_str(), "" | "none")
                    || user.level != 0
                {
                    return Err(Status::unimplemented("unsupported VLESS account settings"));
                }
                let id = uuid::Uuid::parse_str(&account.id)
                    .map_err(|_| Status::invalid_argument("invalid UUID"))?;
                let client = Client::new(user.email.clone(), &account.flow)
                    .map_err(|_| Status::invalid_argument("invalid account"))?;
                {
                    let users = users.read().unwrap();
                    if users
                        .get(&id)
                        .is_some_and(|old| old.email == client.email && old.vision == client.vision)
                    {
                        return Ok(Response::new(AlterInboundResponse {}));
                    }
                    if users.contains_key(&id)
                        || users
                            .values()
                            .any(|old| old.email == client.email && !client.email.is_empty())
                    {
                        return Err(Status::already_exists("user already exists"));
                    }
                }
                account.flow.clear();
                typed.value = account.encode_to_vec();
                self.forward(
                    &request.tag,
                    &op.r#type,
                    AddUserOperation { user: Some(user) }.encode_to_vec(),
                )
                .await?;
                users.write().unwrap().insert(id, client);
            }
            "xray.app.proxyman.command.RemoveUserOperation" => {
                let email = decode::<RemoveUserOperation>(&op.value)?.email;
                let id = users
                    .read()
                    .unwrap()
                    .iter()
                    .find_map(|(id, user)| (user.email == email).then_some(*id))
                    .ok_or_else(|| Status::not_found("user missing"))?;
                self.forward(&request.tag, &op.r#type, op.value).await?;
                if let Some(user) = users.write().unwrap().remove(&id) {
                    user.cancel();
                }
                self.state.stats.remove_online(&email);
            }
            _ => return Err(Status::unimplemented("unsupported inbound operation")),
        }
        Ok(Response::new(AlterInboundResponse {}))
    }

    async fn get_inbound_users(
        &self,
        request: Request<GetInboundUserRequest>,
    ) -> Result<Response<GetInboundUserResponse>, Status> {
        let request = request.into_inner();
        if let Some(users) = self.state.shadowsocks.get(&request.tag) {
            let users = users
                .read()
                .unwrap()
                .values()
                .filter(|client| request.email.is_empty() || client.user.email == request.email)
                .map(|client| User {
                    level: 0,
                    email: client.user.email.clone(),
                    account: Some(TypedMessage {
                        r#type: crate::shadowsocks::ACCOUNT_TYPE.into(),
                        value: client.account().encode_to_vec(),
                    }),
                })
                .collect();
            return Ok(Response::new(GetInboundUserResponse { users }));
        }
        let inbound = self.inbound(&request.tag)?.read().unwrap();
        let users = inbound
            .iter()
            .filter(|(_, user)| request.email.is_empty() || user.email == request.email)
            .map(|(id, user)| {
                let account = Account {
                    id: id.to_string(),
                    flow: if user.vision {
                        VISION.into()
                    } else {
                        String::new()
                    },
                    ..Default::default()
                };
                User {
                    level: 0,
                    email: user.email.clone(),
                    account: Some(TypedMessage {
                        r#type: "xray.proxy.vless.Account".into(),
                        value: account.encode_to_vec(),
                    }),
                }
            })
            .collect();
        Ok(Response::new(GetInboundUserResponse { users }))
    }

    async fn get_inbound_users_count(
        &self,
        request: Request<GetInboundUserRequest>,
    ) -> Result<Response<GetInboundUsersCountResponse>, Status> {
        let tag = request.into_inner().tag;
        let count = if let Some(users) = self.state.shadowsocks.get(&tag) {
            users.read().unwrap().len()
        } else {
            self.inbound(&tag)?.read().unwrap().len()
        } as i64;
        Ok(Response::new(GetInboundUsersCountResponse { count }))
    }
}

fn decode<T: Message + Default>(bytes: &[u8]) -> Result<T, Status> {
    T::decode(bytes).map_err(|_| Status::invalid_argument("invalid protobuf operation"))
}

fn make_stat(name: String, value: i64) -> Response<GetStatsResponse> {
    Response::new(GetStatsResponse {
        stat: Some(Stat { name, value }),
    })
}

fn online_user(name: &str) -> Result<&str, Status> {
    name.strip_prefix("user>>>")
        .and_then(|value| value.strip_suffix(">>>online"))
        .ok_or_else(|| Status::invalid_argument("invalid online counter name"))
}

#[tonic::async_trait]
impl StatsService for Api {
    async fn get_stats(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        let request = request.into_inner();
        if request.name.starts_with("outbound>>>") {
            if let Some(router) = self.backend.go() {
                return stats::stats_service_client::StatsServiceClient::new(
                    router.channel.clone(),
                )
                .get_stats(request)
                .await;
            }
        }
        let counters = self.state.stats.counters.lock().unwrap();
        let value = counters
            .get(&request.name)
            .ok_or_else(|| Status::not_found("counter missing"))?;
        Ok(make_stat(request.name, read_counter(value, request.reset)))
    }

    async fn query_stats(
        &self,
        request: Request<QueryStatsRequest>,
    ) -> Result<Response<QueryStatsResponse>, Status> {
        let request = request.into_inner();
        let mut stat: Vec<_> = {
            let counters = self.state.stats.counters.lock().unwrap();
            counters
                .iter()
                .filter(|(name, _)| name.contains(&request.pattern))
                .map(|(name, value)| Stat {
                    name: name.clone(),
                    value: read_counter(value, request.reset),
                })
                .collect()
        };
        if let Some(router) = self.backend.go()
            && !request.pattern.starts_with("user")
            && !request.pattern.starts_with("inbound")
        {
            let output =
                stats::stats_service_client::StatsServiceClient::new(router.channel.clone())
                    .query_stats(request)
                    .await?
                    .into_inner();
            stat.extend(
                output
                    .stat
                    .into_iter()
                    .filter(|entry| entry.name.starts_with("outbound>>>")),
            );
        }
        Ok(Response::new(QueryStatsResponse { stat }))
    }

    async fn get_sys_stats(
        &self,
        _: Request<SysStatsRequest>,
    ) -> Result<Response<SysStatsResponse>, Status> {
        let uptime = self.state.started.elapsed().as_secs().min(u32::MAX as u64) as u32;
        Ok(Response::new(SysStatsResponse {
            uptime,
            ..Default::default()
        }))
    }

    async fn get_stats_online(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        let name = request.into_inner().name;
        let count = self
            .state
            .stats
            .online()
            .get(online_user(&name)?)
            .map_or(0, |ips| ips.len());
        Ok(make_stat(name, count as i64))
    }

    async fn get_stats_online_ip_list(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsOnlineIpListResponse>, Status> {
        let name = request.into_inner().name;
        let ips = self
            .state
            .stats
            .online()
            .remove(online_user(&name)?)
            .unwrap_or_default();
        Ok(Response::new(GetStatsOnlineIpListResponse { name, ips }))
    }

    async fn get_all_online_users(
        &self,
        _: Request<GetAllOnlineUsersRequest>,
    ) -> Result<Response<GetAllOnlineUsersResponse>, Status> {
        let users = self.state.stats.online().into_keys().collect();
        Ok(Response::new(GetAllOnlineUsersResponse { users }))
    }

    async fn get_users_stats(
        &self,
        request: Request<GetUsersStatsRequest>,
    ) -> Result<Response<GetUsersStatsResponse>, Status> {
        let request = request.into_inner();
        let mut users = std::collections::HashMap::new();
        for (email, ips) in self.state.stats.online() {
            let ips = ips
                .into_iter()
                .map(|(ip, last_seen)| OnlineIpEntry { ip, last_seen })
                .collect();
            users.insert(
                email.clone(),
                UserStat {
                    email,
                    ips,
                    traffic: None,
                },
            );
        }
        if request.include_traffic {
            let counters = self.state.stats.counters.lock().unwrap();
            for (name, value) in counters.iter() {
                let Some((email, direction)) = name
                    .strip_prefix("user>>>")
                    .and_then(|name| name.split_once(">>>traffic>>>"))
                else {
                    continue;
                };
                let user = users.entry(email.to_owned()).or_insert_with(|| UserStat {
                    email: email.to_owned(),
                    ..Default::default()
                });
                let traffic = user.traffic.get_or_insert_default();
                let value = read_counter(value, request.reset);
                if direction == "uplink" {
                    traffic.uplink = value;
                } else {
                    traffic.downlink = value;
                }
            }
        }
        Ok(Response::new(GetUsersStatsResponse {
            users: users.into_values().collect(),
        }))
    }
}
