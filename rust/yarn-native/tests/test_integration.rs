#[cfg(feature = "integration-test")]
mod test {
    use std::future::Future;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use serial_test::serial;
    use yarn_native::{
        AmRmClientBuilder, NmClient, NmClientBuilder, Result, YarnClient, YarnClientBuilder,
        YarnError,
        am::{AllocateRequest, AmRmClient},
        client::ApplicationFilter,
        ids::{ApplicationId, ContainerId, NodeId},
        miniyarn::MiniYarn,
        records::{
            ApplicationState, ApplicationSubmissionContext, Container, ContainerLaunchContext,
            ContainerState, ContainerStatus, FinalApplicationStatus, NodeState, QueueState,
            Resource, ResourceRequest,
        },
    };

    const TIMEOUT: Duration = Duration::from_secs(60);
    const POLL_INTERVAL: Duration = Duration::from_millis(200);
    const TEST_TAG: &str = "yarn-native-test";

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

        test_cluster_info(&client).await.unwrap();
        test_kill_application(&client).await.unwrap();
        test_unmanaged_application_master(&client).await.unwrap();
    }

    async fn test_cluster_info(client: &YarnClient) -> Result<()> {
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

        let missing = client
            .get_application_report(ApplicationId::new(1, 9999))
            .await;
        assert!(
            matches!(missing, Err(YarnError::ApplicationNotFound(_))),
            "{missing:?}"
        );
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

        // A container that writes its environment to a file and exits
        let output = std::env::current_dir()
            .unwrap()
            .join(PathBuf::from(format!("target/test/{}", containers[0].id)));
        let _ = std::fs::remove_file(&output);
        nm.start_container(
            &containers[0],
            ContainerLaunchContext::default()
                .commands(["echo", "$GREETING", ">", output.to_str().unwrap()])
                .env("GREETING", "hello-yarn"),
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
