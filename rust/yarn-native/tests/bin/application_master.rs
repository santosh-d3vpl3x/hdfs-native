use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::time::{Duration, Instant};

use yarn_native::am::AllocateRequest;
use yarn_native::records::{
    ContainerLaunchContext, FinalApplicationStatus, Resource, ResourceRequest,
};
use yarn_native::{AmRmClient, AmRmClientBuilder, Credentials, NmClient, NmClientBuilder};

const AM_RM_TOKEN_KIND: &str = "YARN_AM_RM_TOKEN";
const HDFS_DELEGATION_TOKEN_KIND: &str = "HDFS_DELEGATION_TOKEN";
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const TIMEOUT: Duration = Duration::from_secs(60);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    let am = AmRmClientBuilder::new().build_async().await?;
    let nm = NmClientBuilder::new()
        .with_nm_token_cache(am.nm_token_cache())
        .build_async()
        .await?;

    am.register_application_master("127.0.0.1", port as i32, None)
        .await?;

    let result = serve(&am, &nm, listener).await;
    match result {
        Ok(()) => {
            am.unregister_application_master(FinalApplicationStatus::Succeeded, None, None)
                .await?;
            Ok(())
        }
        Err(err) => {
            let _ = am
                .unregister_application_master(
                    FinalApplicationStatus::Failed,
                    Some(&err.to_string()),
                    None,
                )
                .await;
            Err(err)
        }
    }
}

async fn serve(
    am: &AmRmClient,
    nm: &NmClient,
    listener: TcpListener,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut stream, _) = listener.accept()?;
    writeln!(stream, "yarn-native-test-am")?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        match line.trim() {
            "start" => run_workers(am, nm).await?,
            "stop" => break,
            "" => {}
            other => return Err(format!("unknown command: {other}").into()),
        }
    }
    Ok(())
}

async fn run_workers(am: &AmRmClient, nm: &NmClient) -> Result<(), Box<dyn std::error::Error>> {
    let worker_count: usize = std::env::var("YARN_NATIVE_TEST_WORKERS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    if worker_count == 0 {
        return Ok(());
    }

    let worker_command = std::env::var("YARN_NATIVE_TEST_WORKER_COMMAND").unwrap_or_default();
    let credentials = worker_credentials().await?;

    let mut asks = vec![ResourceRequest::new(
        0,
        Resource::new(128, 1),
        worker_count as i32,
    )];
    let mut containers = Vec::with_capacity(worker_count);
    let start = Instant::now();
    while containers.len() < worker_count {
        if start.elapsed() >= TIMEOUT {
            return Err("timed out allocating worker containers".into());
        }
        let response = am
            .allocate(AllocateRequest {
                asks: std::mem::take(&mut asks),
                progress: 0.1,
                ..Default::default()
            })
            .await?;
        containers.extend(response.allocated_containers);
        if containers.len() < worker_count {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    let mut pending = HashSet::with_capacity(containers.len());
    for container in containers {
        let command = worker_command.replace("{container_id}", &container.id.to_string());
        let mut launch_context = ContainerLaunchContext::default()
            .commands([command])
            .credentials(credentials.clone());
        for variable in ["HADOOP_CONF_DIR", "HADOOP_OPTS", "JAVA_HOME", "KRB5_CONFIG"] {
            if let Ok(value) = std::env::var(variable) {
                launch_context = launch_context.env(variable, value);
            }
        }
        nm.start_container(&container, launch_context).await?;
        pending.insert(container.id);
    }

    let start = Instant::now();
    while !pending.is_empty() {
        if start.elapsed() >= TIMEOUT {
            return Err("timed out waiting for worker containers to complete".into());
        }
        let response = am.allocate(AllocateRequest::default()).await?;
        for status in response.completed_containers {
            if pending.remove(&status.container_id) && status.exit_status != 0 {
                return Err(format!(
                    "worker container {} exited with {}: {}",
                    status.container_id, status.exit_status, status.diagnostics
                )
                .into());
            }
        }
        if !pending.is_empty() {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    Ok(())
}

async fn worker_credentials() -> Result<Credentials, Box<dyn std::error::Error>> {
    let mut credentials = match std::env::var("HADOOP_TOKEN_FILE_LOCATION") {
        Ok(path) if Path::new(&path).exists() => Credentials::read_token_file(Path::new(&path))?,
        _ => Credentials::new(),
    };

    // Workers should not inherit the ApplicationMaster's AMRMToken
    let am_rm_aliases: Vec<String> = credentials
        .tokens()
        .iter()
        .filter(|token| token.kind() == AM_RM_TOKEN_KIND)
        .map(|token| token.alias().to_string())
        .collect();
    for alias in am_rm_aliases {
        credentials.remove_token(&alias);
    }

    if let (Ok(principal), Ok(keytab), Ok(renewer)) = (
        std::env::var("YARN_NATIVE_TEST_PRINCIPAL"),
        std::env::var("YARN_NATIVE_TEST_KEYTAB"),
        std::env::var("YARN_NATIVE_TEST_RENEWER"),
    ) {
        let hdfs_aliases: Vec<String> = credentials
            .tokens()
            .iter()
            .filter(|token| token.kind() == HDFS_DELEGATION_TOKEN_KIND)
            .map(|token| token.alias().to_string())
            .collect();
        for alias in hdfs_aliases {
            credentials.remove_token(&alias);
        }

        let hdfs = hdfs_native::ClientBuilder::new()
            .with_kerberos_principal(principal)
            .with_kerberos_keytab(keytab)
            .build()?;
        let tokens = hdfs.get_delegation_tokens(&renewer).await?;
        credentials.merge(Credentials::from(tokens));
    }

    Ok(credentials)
}
