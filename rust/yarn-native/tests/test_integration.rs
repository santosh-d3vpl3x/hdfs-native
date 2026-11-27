#[cfg(feature = "integration-test")]
mod test {
    use std::collections::HashSet;
    use std::future::Future;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use serial_test::serial;
    use yarn_native::{
        AmRmClientBuilder, Credentials, NmClient, NmClientBuilder, Result, Token, YarnClient,
        YarnClientBuilder, YarnError,
        am::{AllocateRequest, AmRmClient},
        client::ApplicationFilter,
        ids::{ApplicationId, ContainerId, NodeId},
        miniyarn::{MiniYarn, YarnFeatures},
        records::{
            ApplicationState, ApplicationSubmissionContext, Container, ContainerLaunchContext,
            ContainerState, ContainerStatus, FinalApplicationStatus, NodeState, QueueState,
            Resource, ResourceRequest,
        },
    };

    const TIMEOUT: Duration = Duration::from_secs(60);
    const POLL_INTERVAL: Duration = Duration::from_millis(200);
    const TEST_TAG: &str = "yarn-native-test";
    /// The ApplicationMaster in tests/bin/application_master.rs
    const TEST_AM: &str = env!("CARGO_BIN_EXE_yarn-native-test-am");

    fn test_dir() -> PathBuf {
        std::env::current_dir().unwrap().join("target/test")
    }

    /// Submits an application whose ApplicationMaster YARN runs from [`TEST_AM`], waits until
    /// it registers, and connects to the endpoint it registered, as a client of a service
    /// running in YARN would. The ApplicationMaster starts `workers` containers running
    /// `worker_command`, giving them `credentials`.
    async fn start_application_master(
        client: &YarnClient,
        name: &str,
        workers: usize,
        worker_command: &str,
        credentials: Credentials,
    ) -> Result<(ApplicationId, TcpStream)> {
        let application_id = client.create_application().await?.application_id;
        let am_log = test_dir().join(format!("{name}-am.log"));
        let mut am_container = ContainerLaunchContext::default()
            .commands([TEST_AM, "1>", am_log.to_str().unwrap(), "2>&1"])
            .env("HADOOP_CONF_DIR", test_dir().to_str().unwrap())
            .env("RUST_BACKTRACE", "1")
            .env("YARN_NATIVE_TEST_WORKERS", workers.to_string())
            .env("YARN_NATIVE_TEST_WORKER_COMMAND", worker_command)
            .credentials(credentials);
        for variable in ["HADOOP_OPTS", "JAVA_HOME"] {
            if let Ok(value) = std::env::var(variable) {
                am_container = am_container.env(variable, value);
            }
        }
        let mut context = ApplicationSubmissionContext::new(application_id, name);
        context.am_resource = Resource::new(256, 1);
        context.am_container = am_container;
        client.submit_application(context).await?;

        // Clients find the ApplicationMaster's endpoint in the application report
        let report = wait_for("the ApplicationMaster to register", || async {
            let report = client.get_application_report(application_id).await.unwrap();
            assert!(
                !report.state.is_terminal(),
                "{name} ended before registering: {}\n{}",
                report.diagnostics,
                std::fs::read_to_string(&am_log).unwrap_or_default()
            );
            (report.state == ApplicationState::Running && report.rpc_port > 0).then_some(report)
        })
        .await;
        let stream = TcpStream::connect((report.host.as_str(), report.rpc_port as u16))?;
        let mut greeting = String::new();
        BufReader::new(&stream).read_line(&mut greeting)?;
        assert_eq!(greeting.trim(), "yarn-native-test-am");
        Ok((application_id, stream))
    }

    /// Tells the ApplicationMaster to stop and checks the application succeeded.
    async fn stop_application_master(
        client: &YarnClient,
        name: &str,
        application_id: ApplicationId,
        mut stream: TcpStream,
    ) -> Result<()> {
        writeln!(stream, "stop")?;
        let report = wait_for("the application to finish", || async {
            client
                .get_application_report(application_id)
                .await
                .ok()
                .filter(|report| report.state.is_terminal())
        })
        .await;
        assert_eq!(
            (report.state, report.final_status),
            (
                ApplicationState::Finished,
                FinalApplicationStatus::Succeeded
            ),
            "{}\n{}",
            report.diagnostics,
            std::fs::read_to_string(test_dir().join(format!("{name}-am.log"))).unwrap_or_default()
        );
        Ok(())
    }

    /// An empty directory for workers to write to, and a command that writes `output` there,
    /// in a file named after the worker's container.
    fn worker_output(name: &str, output: &str) -> (PathBuf, String) {
        let dir = test_dir().join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let command = format!("{output} > {}/{{container_id}}", dir.display());
        (dir, command)
    }

    fn read_worker_output(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| std::fs::read_to_string(entry.unwrap().path()).unwrap())
            .collect()
    }

    async fn test_application_master_in_yarn(client: &YarnClient) -> Result<()> {
        // A single container: the ApplicationMaster is the whole application
        let (application_id, stream) =
            start_application_master(client, "single-container", 0, "", Credentials::new()).await?;
        stop_application_master(client, "single-container", application_id, stream).await?;

        // A cluster: the ApplicationMaster starts workers
        let (dir, command) = worker_output("cluster-workers", "echo worker");
        let (application_id, stream) =
            start_application_master(client, "cluster", 2, &command, Credentials::new()).await?;
        stop_application_master(client, "cluster", application_id, stream).await?;
        assert_eq!(read_worker_output(&dir), vec!["worker\n"; 2]);
        Ok(())
    }

    /// A Kerberos client submits an application with an HDFS delegation token that the
    /// ResourceManager can renew. The ApplicationMaster hands the token to a worker, whose
    /// Hadoop client reads Kerberized HDFS with it.
    async fn test_application_master_reads_hdfs(client: &YarnClient) -> Result<()> {
        let renewer = client.delegation_token_renewer()?;
        assert!(renewer.starts_with("yarn/localhost@"), "{renewer}");

        let hdfs = hdfs_native::ClientBuilder::new().build().unwrap();
        let path = "/yarn-native-am-input";
        let content = "read by a worker of an ApplicationMaster";
        let mut writer = hdfs
            .create(path, hdfs_native::WriteOptions::default().overwrite(true))
            .await
            .unwrap();
        writer
            .write_bytes(bytes::Bytes::from(content))
            .await
            .unwrap();
        writer.close().await.unwrap();
        // The ResourceManager renews the tokens and refuses applications whose tokens it can't
        let credentials = Credentials::from(hdfs.get_delegation_tokens(&renewer).await.unwrap());

        let hadoop = which::which("hadoop").expect("Failed to find hadoop executable");
        let (dir, command) = worker_output(
            "secure-workers",
            &format!("{} fs -cat {path}", hadoop.display()),
        );
        let (application_id, stream) =
            start_application_master(client, "secure", 1, &command, credentials).await?;
        stop_application_master(client, "secure", application_id, stream).await?;
        assert_eq!(read_worker_output(&dir), vec![content.to_string()]);
        Ok(())
    }

    /// Polls `check` until it returns a value, failing the test after [`TIMEOUT`].
    async fn wait_for<T, F, Fut>(what: &str, mut check: F) -> T
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Option<T>>,
    {
        let start = Instant::now();
        loop {
            if let Some(value) = check().await {
                return value;
            }
            assert!(start.elapsed() < TIMEOUT, "Timed out waiting for {what}");
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_yarn_operations() {
        let _ = env_logger::builder().is_test(true).try_init();
        let _yarn = MiniYarn::default();
        let client = YarnClientBuilder::new().build_async().await.unwrap();

        // Without Kerberos, the ResourceManager knows the client as its OS user
        test_cluster_info(&client, &whoami::username().unwrap())
            .await
            .unwrap();
        test_kill_application(&client).await.unwrap();
        test_unmanaged_application_master(&client).await.unwrap();
        test_application_master_in_yarn(&client).await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_resync_after_resource_manager_restart() {
        let _ = env_logger::builder().is_test(true).try_init();
        let yarn = MiniYarn::with_features(&HashSet::from([YarnFeatures::Recovery]));
        test_application_master_resync(|| yarn.restart_resource_manager()).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_resource_manager_failover() {
        let _ = env_logger::builder().is_test(true).try_init();
        let yarn = MiniYarn::with_features(&HashSet::from([YarnFeatures::HA]));
        test_application_master_resync(|| yarn.fail_over_resource_manager()).await;
    }

    /// Runs an unmanaged ApplicationMaster through `disrupt`, which makes the active
    /// ResourceManager lose it, and checks that the clients find the active ResourceManager,
    /// the ApplicationMaster resyncs and gets its container, and the application finishes.
    async fn test_application_master_resync(disrupt: impl FnOnce()) {
        let client = YarnClientBuilder::new().build_async().await.unwrap();

        let application_id = submit_unmanaged(&client, "resync-test").await.unwrap();
        let token = wait_for("the AMRMToken", || async {
            client.get_am_rm_token(application_id).await.unwrap()
        })
        .await;
        let am = AmRmClientBuilder::new()
            .with_am_rm_token(token)
            .build_async()
            .await
            .unwrap();
        am.register_application_master("localhost", 0, None)
            .await
            .unwrap();

        // The request reaches the ResourceManager, which then loses it
        let response = am
            .allocate(AllocateRequest {
                asks: vec![ResourceRequest::new(0, Resource::new(128, 1), 1)],
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(!response.resynced);
        let mut containers = response.allocated_containers;

        disrupt();

        // The active ResourceManager recovered the application from the state store. It shows
        // as accepted until the ApplicationMaster registers again.
        let report = client.get_application_report(application_id).await.unwrap();
        assert!(
            matches!(
                report.state,
                ApplicationState::Accepted | ApplicationState::Running
            ),
            "{:?}",
            report.state
        );
        assert_eq!(
            client
                .get_cluster_metrics()
                .await
                .unwrap()
                .num_node_managers,
            1
        );

        // The first heartbeat finds the ResourceManager has lost the ApplicationMaster, so the
        // client registers again and re-sends the outstanding request
        let response = am.allocate(AllocateRequest::default()).await.unwrap();
        assert!(response.resynced);
        containers.extend(response.allocated_containers);
        let start = Instant::now();
        while containers.is_empty() {
            assert!(
                start.elapsed() < TIMEOUT,
                "Timed out allocating after a resync"
            );
            tokio::time::sleep(POLL_INTERVAL).await;
            let response = am.allocate(AllocateRequest::default()).await.unwrap();
            assert!(!response.resynced);
            containers.extend(response.allocated_containers);
        }
        assert_eq!(containers.len(), 1);

        am.unregister_application_master(FinalApplicationStatus::Succeeded, None, None)
            .await
            .unwrap();
        let report = wait_for("the application to finish", || async {
            client
                .get_application_report(application_id)
                .await
                .ok()
                .filter(|report| report.state.is_terminal())
        })
        .await;
        assert_eq!(report.final_status, FinalApplicationStatus::Succeeded);
    }

    #[tokio::test]
    #[serial]
    async fn test_security_kerberos() {
        let _ = env_logger::builder().is_test(true).try_init();
        let _yarn = MiniYarn::with_features(&HashSet::from([YarnFeatures::Security]));
        let client = YarnClientBuilder::new().build_async().await.unwrap();

        // The client authenticates as yarn/localhost, which the ResourceManager knows as yarn
        test_cluster_info(&client, "yarn").await.unwrap();
        test_kill_application(&client).await.unwrap();

        // The ResourceManager only returns an unmanaged AMRMToken to a caller whose user name is
        // the application's user, which a Kerberos principal's full name never is. Submitting
        // as an impersonated user, like a gateway service would, makes them match.
        let proxy_client = YarnClientBuilder::new()
            .with_user("yarn")
            .build_async()
            .await
            .unwrap();
        test_container_reads_hdfs_with_a_delegation_token(&proxy_client)
            .await
            .unwrap();

        // An ApplicationMaster that YARN runs gets its AMRMToken from its token file, so a
        // Kerberos submitter needs no impersonation
        test_application_master_reads_hdfs(&client).await.unwrap();
    }

    /// An ApplicationMaster gets an HDFS delegation token and hands it to a container, whose
    /// Hadoop client reads Kerberized HDFS with it. A container without the token cannot.
    async fn test_container_reads_hdfs_with_a_delegation_token(client: &YarnClient) -> Result<()> {
        let hdfs = hdfs_native::ClientBuilder::new().build().unwrap();
        let path = "/yarn-native-input";
        let content = b"read by a container with a delegation token";
        let mut writer = hdfs
            .create(path, hdfs_native::WriteOptions::default().overwrite(true))
            .await
            .unwrap();
        writer
            .write_bytes(bytes::Bytes::from_static(content))
            .await
            .unwrap();
        writer.close().await.unwrap();
        let hdfs_tokens = hdfs.get_delegation_tokens("yarn").await.unwrap();

        let application_id = submit_unmanaged(client, "secure-container-test").await?;
        let token = wait_for("the AMRMToken", || async {
            client.get_am_rm_token(application_id).await.unwrap()
        })
        .await;
        let am = AmRmClientBuilder::new()
            .with_am_rm_token(token)
            .build_async()
            .await?;
        am.register_application_master("localhost", 0, None).await?;
        let containers = allocate_containers(&am, 2).await?;
        let nm = NmClientBuilder::new()
            .with_nm_token_cache(am.nm_token_cache())
            .build_async()
            .await?;

        let hadoop = which::which("hadoop").expect("Failed to find hadoop executable");
        let test_dir = std::env::current_dir().unwrap().join("target/test");
        let read_hdfs = |name: &str| {
            let mut context = ContainerLaunchContext::default()
                .commands([
                    hadoop.to_str().unwrap().to_string(),
                    "fs".to_string(),
                    "-cat".to_string(),
                    path.to_string(),
                    ">".to_string(),
                    test_dir
                        .join(format!("{name}.out"))
                        .to_str()
                        .unwrap()
                        .to_string(),
                    "2>".to_string(),
                    test_dir
                        .join(format!("{name}.err"))
                        .to_str()
                        .unwrap()
                        .to_string(),
                ])
                .env("HADOOP_CONF_DIR", test_dir.to_str().unwrap())
                .env("HADOOP_OPTS", std::env::var("HADOOP_OPTS").unwrap());
            if let Ok(java_home) = std::env::var("JAVA_HOME") {
                context = context.env("JAVA_HOME", java_home);
            }
            context
        };

        let with_token = &containers[0];
        nm.start_container(
            with_token,
            read_hdfs("with-token").credentials(Credentials::from(hdfs_tokens)),
        )
        .await?;
        let without_token = &containers[1];
        nm.start_container(without_token, read_hdfs("without-token"))
            .await?;

        let status = wait_for_container_state(
            &nm,
            with_token.id,
            &with_token.node_id,
            ContainerState::Complete,
        )
        .await;
        assert_eq!(
            status.exit_status,
            0,
            "{}",
            std::fs::read_to_string(test_dir.join("with-token.err")).unwrap_or_default()
        );
        assert_eq!(
            std::fs::read(test_dir.join("with-token.out"))?,
            content.to_vec()
        );

        let status = wait_for_container_state(
            &nm,
            without_token.id,
            &without_token.node_id,
            ContainerState::Complete,
        )
        .await;
        assert_ne!(status.exit_status, 0);

        am.unregister_application_master(FinalApplicationStatus::Succeeded, None, None)
            .await?;
        Ok(())
    }

    async fn test_cluster_info(client: &YarnClient, user: &str) -> Result<()> {
        let metrics = client.get_cluster_metrics().await?;
        assert_eq!(metrics.num_node_managers, 1);
        assert_eq!(metrics.num_active_node_managers, 1);

        let nodes = client.get_nodes(&[]).await?;
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].state, NodeState::Running);
        assert_eq!(nodes[0].capability.memory_mb, 4096);
        assert!(client.get_nodes(&[NodeState::Lost]).await?.is_empty());

        let queue = client.get_queue_info("default").await?;
        assert_eq!(queue.queue_name, "default");
        assert_eq!(queue.state, QueueState::Running);

        test_delegation_tokens(client, user).await?;

        let missing = client
            .get_application_report(ApplicationId::new(1, 9999))
            .await;
        assert!(
            matches!(missing, Err(YarnError::ApplicationNotFound(_))),
            "{missing:?}"
        );
        Ok(())
    }

    /// `renewer` must be the client's user, since only the renewer may renew.
    async fn test_delegation_tokens(client: &YarnClient, renewer: &str) -> Result<()> {
        let token = client.get_delegation_token(renewer).await?;
        assert_eq!(token.kind(), "RM_DELEGATION_TOKEN");
        let address = std::fs::read_to_string("target/test/yarn-site.xml")?;
        let port = token.service().rsplit_once(':').unwrap().1;
        assert!(
            address.contains(&format!("localhost:{port}")),
            "{}",
            token.service()
        );

        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(client.renew_delegation_token(&token).await? > now_millis);

        client.cancel_delegation_token(&token).await?;
        let renewed = client.renew_delegation_token(&token).await;
        assert!(renewed.is_err(), "{renewed:?}");
        Ok(())
    }

    async fn submit_unmanaged(client: &YarnClient, name: &str) -> Result<ApplicationId> {
        let new_application = client.create_application().await?;
        assert!(new_application.maximum_resource_capability.memory_mb > 0);

        let mut context = ApplicationSubmissionContext::new(new_application.application_id, name);
        context.unmanaged_am = true;
        context.tags = vec![TEST_TAG.to_string()];
        let application_id = client.submit_application(context).await?;
        assert_eq!(application_id, new_application.application_id);
        Ok(application_id)
    }

    async fn test_kill_application(client: &YarnClient) -> Result<()> {
        let application_id = submit_unmanaged(client, "kill-test").await?;

        let listed = client
            .get_applications(&ApplicationFilter {
                tags: vec![TEST_TAG.to_string()],
                ..Default::default()
            })
            .await?;
        assert!(
            listed
                .iter()
                .any(|report| report.application_id == application_id)
        );

        client
            .kill_application(application_id, Some("killed by test"))
            .await?;
        // The ResourceManager reports kills of unmanaged applications complete right away, so
        // the state can lag behind
        let report = wait_for("the application to be killed", || async {
            client
                .get_application_report(application_id)
                .await
                .ok()
                .filter(|report| report.state.is_terminal())
        })
        .await;
        assert_eq!(report.state, ApplicationState::Killed);
        assert!(
            report.diagnostics.ends_with("killed by test"),
            "{}",
            report.diagnostics
        );
        assert!(
            client
                .get_applications(&ApplicationFilter {
                    states: vec![ApplicationState::Running],
                    tags: vec![TEST_TAG.to_string()],
                    ..Default::default()
                })
                .await?
                .is_empty()
        );
        Ok(())
    }

    async fn allocate_containers(am: &AmRmClient, count: usize) -> Result<Vec<Container>> {
        // A request replaces the outstanding one, so ask once and then just heartbeat
        let mut asks = vec![ResourceRequest::new(0, Resource::new(128, 1), count as i32)];
        let mut containers = Vec::new();
        let start = Instant::now();
        while containers.len() < count {
            assert!(start.elapsed() < TIMEOUT, "Timed out allocating containers");
            let response = am
                .allocate(AllocateRequest {
                    asks: std::mem::take(&mut asks),
                    progress: 0.1,
                    ..Default::default()
                })
                .await?;
            assert_eq!(response.num_cluster_nodes, 1);
            assert!(response.am_command.is_none());
            containers.extend(response.allocated_containers);
            tokio::time::sleep(POLL_INTERVAL).await;
        }
        Ok(containers)
    }

    async fn wait_for_container_state(
        nm: &NmClient,
        container_id: ContainerId,
        node_id: &NodeId,
        state: ContainerState,
    ) -> ContainerStatus {
        wait_for(&format!("{container_id} to be {state:?}"), || async {
            nm.get_container_status(container_id, node_id)
                .await
                .ok()
                .filter(|status| status.state == state)
        })
        .await
    }

    async fn test_unmanaged_application_master(client: &YarnClient) -> Result<()> {
        let application_id = submit_unmanaged(client, "unmanaged-am-test").await?;

        // The token is available once the ResourceManager launches the unmanaged attempt
        let token = wait_for("the AMRMToken", || async {
            client.get_am_rm_token(application_id).await.unwrap()
        })
        .await;
        assert_eq!(token.kind(), "YARN_AM_RM_TOKEN");

        let am = AmRmClientBuilder::new()
            .with_am_rm_token(token)
            .build_async()
            .await?;
        let registration = am
            .register_application_master("localhost", 0, Some("http://localhost/tracking"))
            .await?;
        assert!(registration.maximum_resource_capability.memory_mb >= 128);
        assert_eq!(registration.queue, "root.default");

        let report = client.get_application_report(application_id).await?;
        assert_eq!(report.state, ApplicationState::Running);
        let attempt_id = report
            .current_attempt_id
            .expect("running app has an attempt");
        let attempts = client.get_application_attempts(application_id).await?;
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].attempt_id, attempt_id);
        assert_eq!(
            client
                .get_application_attempt_report(attempt_id)
                .await?
                .attempt_id,
            attempt_id
        );

        let containers = allocate_containers(&am, 2).await?;
        for container in &containers {
            assert_eq!(container.id.application_attempt_id, attempt_id);
            assert!(container.container_token.is_some());
            assert!(
                am.nm_token_cache().get(&container.node_id).is_some(),
                "NMToken for {}",
                container.node_id
            );
        }

        let nm = NmClientBuilder::new()
            .with_nm_token_cache(am.nm_token_cache())
            .build_async()
            .await?;

        // A container that writes its environment and its token file out, then exits
        let output = std::env::current_dir()
            .unwrap()
            .join(PathBuf::from(format!("target/test/{}", containers[0].id)));
        let tokens_output = output.with_extension("tokens");
        let _ = std::fs::remove_file(&output);
        let _ = std::fs::remove_file(&tokens_output);
        let mut credentials = Credentials::new();
        credentials.add_token(
            "nn:8020",
            Token::new(
                b"identifier".to_vec(),
                b"password".to_vec(),
                "HDFS_DELEGATION_TOKEN",
                "nn:8020",
            ),
        );
        credentials.add_secret_key("secret", b"key".to_vec());
        nm.start_container(
            &containers[0],
            ContainerLaunchContext::default()
                .commands([
                    "echo",
                    "$GREETING",
                    ">",
                    output.to_str().unwrap(),
                    "&&",
                    "cp",
                    "\"$HADOOP_TOKEN_FILE_LOCATION\"",
                    tokens_output.to_str().unwrap(),
                ])
                .env("GREETING", "hello-yarn")
                .credentials(credentials.clone()),
        )
        .await?;
        let status = wait_for_container_state(
            &nm,
            containers[0].id,
            &containers[0].node_id,
            ContainerState::Complete,
        )
        .await;
        assert_eq!(status.exit_status, 0, "{}", status.diagnostics);
        assert_eq!(std::fs::read_to_string(&output)?.trim(), "hello-yarn");
        // The NodeManager (Java) parsed our credentials and wrote them back for the container
        let container_credentials = Credentials::read_token_file(&tokens_output)?;
        assert_eq!(
            container_credentials.token("nn:8020"),
            credentials.token("nn:8020")
        );
        assert_eq!(
            container_credentials.secret_key("secret"),
            Some(&b"key"[..])
        );

        // Starting the same container again fails for that container only
        let restart = nm
            .start_container(&containers[0], ContainerLaunchContext::default())
            .await;
        assert!(
            matches!(restart, Err(YarnError::ContainerError(ref id, _, _)) if *id == containers[0].id.to_string()),
            "{restart:?}"
        );

        // A long-running container that the ApplicationMaster stops
        nm.start_container(
            &containers[1],
            ContainerLaunchContext::default().commands(["sleep", "600"]),
        )
        .await?;
        wait_for_container_state(
            &nm,
            containers[1].id,
            &containers[1].node_id,
            ContainerState::Running,
        )
        .await;
        // The ResourceManager only reports on containers that are still running, unless a
        // timeline server keeps their history
        let container_report = client.get_container_report(containers[1].id).await?;
        assert_eq!(container_report.container_id, containers[1].id);
        assert_eq!(container_report.node_id, containers[1].node_id);
        assert_eq!(container_report.state, ContainerState::Running);
        nm.stop_container(containers[1].id, &containers[1].node_id)
            .await?;
        let status = wait_for_container_state(
            &nm,
            containers[1].id,
            &containers[1].node_id,
            ContainerState::Complete,
        )
        .await;
        assert_ne!(status.exit_status, 0);

        // The ResourceManager reports both containers as completed
        let mut completed = Vec::new();
        let start = Instant::now();
        while completed.len() < 2 {
            assert!(
                start.elapsed() < TIMEOUT,
                "Timed out waiting for completed containers"
            );
            let response = am.allocate(AllocateRequest::default()).await?;
            completed.extend(
                response
                    .completed_containers
                    .into_iter()
                    .map(|status| status.container_id),
            );
            tokio::time::sleep(POLL_INTERVAL).await;
        }
        assert!(completed.contains(&containers[0].id));
        assert!(completed.contains(&containers[1].id));

        am.unregister_application_master(FinalApplicationStatus::Succeeded, Some("done"), None)
            .await?;
        let report = wait_for("the application to finish", || async {
            client
                .get_application_report(application_id)
                .await
                .ok()
                .filter(|report| report.state.is_terminal())
        })
        .await;
        assert_eq!(report.state, ApplicationState::Finished);
        assert_eq!(report.final_status, FinalApplicationStatus::Succeeded);
        Ok(())
    }
}
