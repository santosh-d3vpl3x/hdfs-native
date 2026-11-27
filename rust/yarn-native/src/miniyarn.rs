use std::{
    env,
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
};
#[cfg(unix)]
use std::{
    thread,
    time::{Duration, Instant},
};
use which::which;

#[cfg(unix)]
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(unix)]
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// A MiniYARNCluster with one ResourceManager and one NodeManager, for integration tests.
///
/// Starting it writes the cluster's `yarn-site.xml` to `target/test` and points
/// `HADOOP_CONF_DIR` there, so clients built with default settings connect to it.
pub struct MiniYarn {
    process: Child,
}

impl MiniYarn {
    pub fn new() -> Self {
        let mvn_exec = which("mvn").expect("Failed to find mvn executable");

        let mut command = Command::new(mvn_exec);
        command
            .args([
                "-f",
                concat!(env!("OUT_DIR"), "/miniyarn"),
                "--quiet",
                "--errors",
                "compile",
                "exec:exec",
                "-Dexec.args=-cp %classpath main.Main",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        // Maven's exec:exec goal starts the MiniYARNCluster JVM as a child process.
        // Keep it in the same process group so Drop can terminate both.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }

        let mut child = command.spawn().unwrap();

        let mut output = BufReader::new(child.stdout.take().unwrap()).lines();

        let ready = output.next().unwrap().unwrap();
        if ready != "Ready!" {
            println!("Failed to start miniyarn");
            println!("{ready}");
            for line in output.by_ref() {
                println!("{}", line.unwrap());
            }
            panic!();
        }

        // Make sure an AMRMToken file from another test isn't picked up
        unsafe { env::remove_var("HADOOP_TOKEN_FILE_LOCATION") };
        unsafe { env::set_var("HADOOP_CONF_DIR", "target/test") };
        MiniYarn { process: child }
    }
}

impl Default for MiniYarn {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for MiniYarn {
    fn drop(&mut self) {
        println!("Dropping and killing miniyarn");
        terminate_process_tree(&mut self.process);
        let _ = self.process.wait();
    }
}

#[cfg(unix)]
fn terminate_process_tree(child: &mut Child) {
    let process_group = child.id() as libc::pid_t;
    signal_process_group(process_group, libc::SIGTERM);
    if !wait_for_process_group_exit(child, process_group, SHUTDOWN_TIMEOUT) {
        signal_process_group(process_group, libc::SIGKILL);
    }
}

#[cfg(unix)]
fn wait_for_process_group_exit(
    child: &mut Child,
    process_group: libc::pid_t,
    timeout: Duration,
) -> bool {
    let start = Instant::now();
    loop {
        if let Err(error) = child.try_wait() {
            eprintln!("Failed to check MiniYARN process status: {error}");
        }

        // Maven exits before its Java child has finished running shutdown hooks,
        // so check the whole process group instead of only the Maven process.
        if !process_group_exists(process_group) {
            return true;
        }

        if start.elapsed() >= timeout {
            return false;
        }
        thread::sleep(PROCESS_POLL_INTERVAL);
    }
}

#[cfg(unix)]
fn process_group_exists(process_group: libc::pid_t) -> bool {
    if unsafe { libc::kill(-process_group, 0) } == 0 {
        return true;
    }

    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => false,
        Some(libc::EPERM) => true,
        _ => true,
    }
}

#[cfg(unix)]
fn signal_process_group(process_group: libc::pid_t, signal: libc::c_int) {
    // SAFETY: process_group is the process group ID assigned to the Maven
    // child in with_features; a negative PID targets only that group.
    if unsafe { libc::kill(-process_group, signal) } == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            eprintln!("Failed to signal MiniYARN process group: {error}");
        }
    }
}

#[cfg(windows)]
fn terminate_process_tree(child: &mut Child) {
    let pid = child.id().to_string();
    let result = Command::new("taskkill")
        .arg("/PID")
        .arg(pid)
        .arg("/T")
        .arg("/F")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if !matches!(result, Ok(status) if status.success()) {
        let _ = child.kill();
    }
}

#[cfg(not(any(unix, windows)))]
fn terminate_process_tree(child: &mut Child) {
    let _ = child.kill();
}
