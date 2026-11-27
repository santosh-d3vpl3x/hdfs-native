use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hadoop_native::security::user::Token;
use log::{debug, info};

use crate::client::{ClientContext, ClientOptions, RuntimeHolder, client_options_methods};
use crate::config;
use crate::ids::{ContainerId, NodeId};
use crate::proto::yarn::{
    self, AllocateRequestProto, FinalApplicationStatusProto, NmTokenProto,
    RegisterApplicationMasterRequestProto, ResourceBlacklistRequestProto,
};
use crate::proxy::ServiceProxy;
use crate::records::{
    AmCommand, Container, ContainerStatus, FinalApplicationStatus, NodeReport, Resource,
    ResourceRequest,
};
use crate::resourcemanager::master_protocol::{self, ApplicationMasterProtocol};
use crate::{Result, YarnError};

/// How long to wait between attempts to unregister, like Hadoop's `AMRMClientImpl`.
const UNREGISTER_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// NMTokens of an application attempt, keyed by node. The ResourceManager hands these out in
/// allocate responses; [`NmClient`](crate::NmClient) needs the token for a node to talk to it.
/// Clones share the same tokens.
#[derive(Clone, Debug, Default)]
pub struct NmTokenCache {
    tokens: Arc<Mutex<HashMap<NodeId, Token>>>,
}

impl NmTokenCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, node_id: &NodeId) -> Option<Token> {
        self.tokens.lock().unwrap().get(node_id).cloned()
    }

    pub fn insert(&self, node_id: NodeId, token: Token) {
        self.tokens.lock().unwrap().insert(node_id, token);
    }

    pub fn remove(&self, node_id: &NodeId) -> Option<Token> {
        self.tokens.lock().unwrap().remove(node_id)
    }

    pub fn len(&self) -> usize {
        self.tokens.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn insert_all(&self, nm_tokens: Vec<NmTokenProto>) {
        let mut tokens = self.tokens.lock().unwrap();
        for nm_token in nm_tokens {
            if let (Some(node_id), Some(token)) = (nm_token.node_id, nm_token.token) {
                let node_id = NodeId::from(node_id);
                debug!("Received NMToken for {node_id}");
                tokens.insert(node_id, token.into());
            }
        }
    }
}

/// Builds a new [AmRmClient] instance.
///
/// The client authenticates with the attempt's AMRMToken. By default it is read from the token
/// file in `HADOOP_TOKEN_FILE_LOCATION`, which YARN sets for ApplicationMaster containers. An
/// unmanaged ApplicationMaster gets its token from
/// [`YarnClient::get_am_rm_token`](crate::YarnClient::get_am_rm_token) and passes it to
/// [`Self::with_am_rm_token`].
#[derive(Default)]
pub struct AmRmClientBuilder {
    options: ClientOptions,
    am_rm_token: Option<Token>,
    nm_tokens: Option<NmTokenCache>,
}

impl AmRmClientBuilder {
    /// Create a new [AmRmClientBuilder]
    pub fn new() -> Self {
        Self::default()
    }

    client_options_methods!();

    /// Set the AMRMToken to authenticate with instead of reading it from the token file.
    pub fn with_am_rm_token(mut self, token: Token) -> Self {
        self.am_rm_token = Some(token);
        self
    }

    /// Store received NMTokens in `cache` instead of a new cache.
    pub fn with_nm_token_cache(mut self, cache: NmTokenCache) -> Self {
        self.nm_tokens = Some(cache);
        self
    }

    /// Synchronously create the [AmRmClient] instance from the provided settings.
    pub fn build(mut self) -> Result<AmRmClient> {
        let options = std::mem::take(&mut self.options);
        self.build_with_context(options.build_context()?)
    }

    /// Asynchronously create an [AmRmClient] instance, loading XML config files without
    /// blocking a Tokio worker thread.
    pub async fn build_async(mut self) -> Result<AmRmClient> {
        let options = std::mem::take(&mut self.options);
        self.build_with_context(options.build_context_async().await?)
    }

    fn build_with_context(self, context: ClientContext) -> Result<AmRmClient> {
        let mut token = match self.am_rm_token {
            Some(token) => token,
            None => Token::from_token_file_env()
                .into_iter()
                .find(|token| token.kind() == master_protocol::PROTOCOL.token_kind)
                .ok_or_else(|| {
                    YarnError::InvalidArgument(format!(
                        "No {} found in HADOOP_TOKEN_FILE_LOCATION; pass one with with_am_rm_token",
                        master_protocol::PROTOCOL.token_kind
                    ))
                })?,
        };

        let addresses = context.config.rm_addresses(
            config::RM_SCHEDULER_ADDRESS,
            config::DEFAULT_RM_SCHEDULER_PORT,
        )?;
        // Like Hadoop's ClientRMProxy, point the token at the scheduler addresses
        let token_service = context.config.rm_token_service(&addresses);
        token.set_service(token_service.clone());

        let proxy = ServiceProxy::new(
            master_protocol::PROTOCOL,
            addresses,
            token_service,
            Some(token),
            context.config.rm_failover_settings(),
            Arc::clone(&context.config),
            context.rt_holder.get_handle(),
            context.user,
            context.auth,
        )?;

        Ok(AmRmClient {
            protocol: Arc::new(ApplicationMasterProtocol::new(proxy)),
            nm_tokens: self.nm_tokens.unwrap_or_default(),
            last_response_id: Arc::new(tokio::sync::Mutex::new(0)),
            rt_holder: context.rt_holder,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RegisterResponse {
    /// The most resources the cluster grants a single container.
    pub maximum_resource_capability: Resource,
    pub queue: String,
    /// Containers kept from earlier attempts when the application keeps containers across
    /// attempts.
    pub containers_from_previous_attempts: Vec<Container>,
}

/// A heartbeat to the ResourceManager. See [`ResourceRequest`] for how asks replace
/// outstanding requests.
#[derive(Debug, Clone, Default)]
pub struct AllocateRequest {
    pub asks: Vec<ResourceRequest>,
    /// Containers the application no longer needs.
    pub releases: Vec<ContainerId>,
    /// Progress of the application between 0 and 1.
    pub progress: f32,
    /// Hosts or racks to stop allocating containers on.
    pub blacklist_additions: Vec<String>,
    pub blacklist_removals: Vec<String>,
    pub tracking_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AllocateResponse {
    pub allocated_containers: Vec<Container>,
    pub completed_containers: Vec<ContainerStatus>,
    /// Resources the application can still be allocated.
    pub available_resources: Resource,
    pub updated_nodes: Vec<NodeReport>,
    pub num_cluster_nodes: i32,
    /// When set, the ApplicationMaster must resync (register again) or shut down.
    pub am_command: Option<AmCommand>,
}

/// A client to the ResourceManager's scheduler, for an application's ApplicationMaster.
///
/// The ApplicationMaster registers, then calls [`Self::allocate`] periodically as a heartbeat to
/// request and release containers, and finally unregisters. Allocated containers are started
/// with an [`NmClient`](crate::NmClient) that shares this client's [`NmTokenCache`].
#[derive(Clone, Debug)]
pub struct AmRmClient {
    protocol: Arc<ApplicationMasterProtocol>,
    nm_tokens: NmTokenCache,
    // The ResourceManager rejects an allocate whose response ID does not follow the last one,
    // so allocate calls are serialized.
    last_response_id: Arc<tokio::sync::Mutex<i32>>,
    #[allow(dead_code)]
    rt_holder: RuntimeHolder,
}

impl AmRmClient {
    /// The cache that NMTokens from this ResourceManager are stored in.
    pub fn nm_token_cache(&self) -> NmTokenCache {
        self.nm_tokens.clone()
    }

    /// Registers the ApplicationMaster. `host`, `rpc_port` and `tracking_url` are shown to
    /// clients in the application report.
    pub async fn register_application_master(
        &self,
        host: &str,
        rpc_port: i32,
        tracking_url: Option<&str>,
    ) -> Result<RegisterResponse> {
        let response = self
            .protocol
            .register_application_master(RegisterApplicationMasterRequestProto {
                host: Some(host.to_string()),
                rpc_port: Some(rpc_port),
                tracking_url: tracking_url.map(str::to_string),
                ..Default::default()
            })
            .await?;
        *self.last_response_id.lock().await = 0;
        self.nm_tokens
            .insert_all(response.nm_tokens_from_previous_attempts);

        Ok(RegisterResponse {
            maximum_resource_capability: response.maximum_capability.unwrap_or_default().into(),
            queue: response.queue.unwrap_or_default(),
            containers_from_previous_attempts: response
                .containers_from_previous_attempts
                .into_iter()
                .map(Into::into)
                .collect(),
        })
    }

    /// Sends a heartbeat that asks for and releases containers. NMTokens in the response are
    /// stored in the [`NmTokenCache`], and a rolled AMRMToken is used for new connections.
    pub async fn allocate(&self, request: AllocateRequest) -> Result<AllocateResponse> {
        let blacklist_request =
            if request.blacklist_additions.is_empty() && request.blacklist_removals.is_empty() {
                None
            } else {
                Some(ResourceBlacklistRequestProto {
                    blacklist_additions: request.blacklist_additions,
                    blacklist_removals: request.blacklist_removals,
                })
            };

        let mut last_response_id = self.last_response_id.lock().await;
        let response = self
            .protocol
            .allocate(AllocateRequestProto {
                ask: request.asks.into_iter().map(Into::into).collect(),
                release: request.releases.into_iter().map(Into::into).collect(),
                blacklist_request,
                response_id: Some(*last_response_id),
                progress: Some(request.progress),
                tracking_url: request.tracking_url,
                ..Default::default()
            })
            .await?;
        *last_response_id = response.response_id();
        drop(last_response_id);

        let num_cluster_nodes = response.num_cluster_nodes();
        self.nm_tokens.insert_all(response.nm_tokens);
        if let Some(am_rm_token) = response.am_rm_token {
            info!("Received a new AMRMToken");
            let mut token = Token::from(am_rm_token);
            token.set_service(self.protocol.token_service());
            self.protocol.set_token(token);
        }

        Ok(AllocateResponse {
            am_command: response
                .a_m_command
                .and_then(|command| yarn::AmCommandProto::try_from(command).ok())
                .map(Into::into),
            num_cluster_nodes,
            allocated_containers: response
                .allocated_containers
                .into_iter()
                .map(Into::into)
                .collect(),
            completed_containers: response
                .completed_container_statuses
                .into_iter()
                .map(Into::into)
                .collect(),
            available_resources: response.limit.unwrap_or_default().into(),
            updated_nodes: response.updated_nodes.into_iter().map(Into::into).collect(),
        })
    }

    /// Unregisters the ApplicationMaster with its final status, waiting until the
    /// ResourceManager confirms, like Hadoop's `AMRMClient.unregisterApplicationMaster`.
    pub async fn unregister_application_master(
        &self,
        status: FinalApplicationStatus,
        diagnostics: Option<&str>,
        tracking_url: Option<&str>,
    ) -> Result<()> {
        let request = yarn::FinishApplicationMasterRequestProto {
            diagnostics: diagnostics.map(str::to_string),
            tracking_url: tracking_url.map(str::to_string),
            final_application_status: Some(FinalApplicationStatusProto::from(status) as i32),
        };
        loop {
            let response = self
                .protocol
                .finish_application_master(request.clone())
                .await?;
            if response.is_unregistered() {
                return Ok(());
            }
            tokio::time::sleep(UNREGISTER_POLL_INTERVAL).await;
        }
    }

    /// The AMRMToken new connections authenticate with.
    pub fn am_rm_token(&self) -> Option<Token> {
        self.protocol.token()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::proto::common::TokenProto;
    use crate::proto::yarn::NodeIdProto;

    fn token() -> Token {
        Token::new(b"id".to_vec(), b"pw".to_vec(), "YARN_AM_RM_TOKEN", "")
    }

    #[test]
    fn test_build_points_the_token_at_the_scheduler() {
        let client = AmRmClientBuilder::new()
            .with_config([
                ("yarn.resourcemanager.scheduler.address", "127.0.0.1:18030"),
                ("hadoop.security.token.service.use_ip", "false"),
            ])
            .with_am_rm_token(token())
            .build()
            .unwrap();
        assert_eq!(client.am_rm_token().unwrap().service(), "127.0.0.1:18030");
    }

    #[test]
    fn test_build_without_a_token_fails() {
        // SAFETY: tests in this crate don't read this variable concurrently
        unsafe { std::env::remove_var("HADOOP_TOKEN_FILE_LOCATION") };
        assert!(matches!(
            AmRmClientBuilder::new().build(),
            Err(YarnError::InvalidArgument(_))
        ));
    }

    #[test]
    fn test_nm_token_cache_stores_received_tokens() {
        let cache = NmTokenCache::new();
        cache.insert_all(vec![
            NmTokenProto {
                node_id: Some(NodeIdProto {
                    host: Some("nm".to_string()),
                    port: Some(1),
                }),
                token: Some(TokenProto {
                    identifier: b"id".to_vec(),
                    password: b"pw".to_vec(),
                    kind: "NMToken".to_string(),
                    service: "nm:1".to_string(),
                }),
            },
            // Incomplete entries are ignored
            NmTokenProto {
                node_id: None,
                token: None,
            },
        ]);
        assert_eq!(cache.len(), 1);
        let shared = cache.clone();
        assert_eq!(shared.get(&NodeId::new("nm", 1)).unwrap().kind(), "NMToken");
    }
}
