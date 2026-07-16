#![cfg(unix)]

use p00_durable_jobs::{CompletionOutcome, JobOutput, JobStore, NewJob, StoreError};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const BARRIER_TIMEOUT: Duration = Duration::from_secs(10);

struct Helper {
    child: Option<Child>,
    process_group: i32,
    reader: Option<JoinHandle<Result<String, String>>>,
}

impl Helper {
    fn kill_group_and_wait(mut self) -> i32 {
        let result = unsafe { libc::kill(-self.process_group, libc::SIGKILL) };
        assert_eq!(result, 0, "SIGKILL exact helper process group");

        let status = self
            .child
            .take()
            .expect("armed helper child")
            .wait()
            .expect("wait for killed helper");
        let signal = status.signal();
        assert_eq!(
            signal,
            Some(libc::SIGKILL),
            "helper did not terminate specifically by SIGKILL: {status}"
        );
        self.join_reader_after_cleanup();
        signal.unwrap()
    }

    fn read_barrier(&mut self) -> Result<String, String> {
        self.reader
            .take()
            .ok_or_else(|| "helper reader was not armed".to_string())?
            .join()
            .map_err(|_| "helper reader thread panicked".to_string())?
    }

    fn join_reader_after_cleanup(&mut self) {
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            unsafe {
                libc::kill(-self.process_group, libc::SIGKILL);
            }
            let _ = child.wait();
        }
        self.join_reader_after_cleanup();
    }
}

fn job() -> NewJob {
    NewJob {
        id: "job-1".into(),
        idempotency_key: "request-1".into(),
        kind: "thumbnail".into(),
        payload_version: 1,
        payload: json!({"asset": "asset-1"}),
        normalized_input_hash: "input-hash".into(),
        pipeline_version: "pipeline-v1".into(),
    }
}

fn output(worker: &str) -> JobOutput {
    JobOutput {
        output_key: "output-1".into(),
        result_hash: "result-hash".into(),
        output: json!({"produced_by": worker}),
    }
}

fn fixture() -> (TempDir, PathBuf, JobStore) {
    let directory = TempDir::new().unwrap();
    let database = directory.path().join("jobs.sqlite");
    let store = JobStore::open(&database).unwrap();
    store.enqueue(&job(), 100).unwrap();
    (directory, database, store)
}

fn helper_command(mode: &str, database: &Path, extra: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_p00-job-helper"));
    command
        .arg(mode)
        .arg(database)
        .args(extra)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    command
}

fn spawn_barrier(mut command: Command) -> (Helper, Value) {
    let child = command.spawn().expect("spawn helper");
    let process_group = child.id() as i32;
    let mut helper = Helper {
        child: Some(child),
        process_group,
        reader: None,
    };
    let actual_process_group = unsafe { libc::getpgid(process_group) };
    assert_eq!(
        actual_process_group, process_group,
        "helper must lead its exact process group"
    );

    let stdout = helper
        .child
        .as_mut()
        .expect("armed helper child")
        .stdout
        .take()
        .expect("helper stdout");
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout)
            .read_line(&mut line)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                if bytes == 0 {
                    Err("helper closed stdout before a barrier".into())
                } else {
                    Ok(line)
                }
            });
        let _ = sender.send(());
        result
    });
    helper.reader = Some(reader);
    if let Err(error) = receiver.recv_timeout(BARRIER_TIMEOUT) {
        helper.kill_group_and_wait();
        panic!("helper barrier timeout: {error}");
    }

    let line = match helper.read_barrier() {
        Ok(line) => line,
        Err(error) => {
            helper.kill_group_and_wait();
            panic!("read helper barrier: {error}");
        }
    };
    let value: Value = serde_json::from_str(&line).expect("JSON helper barrier");
    assert!(value.get("error").is_none(), "helper failed: {value}");
    (helper, value)
}

fn run_helper(mode: &str, database: &Path, extra: &[&str]) -> Value {
    let output = helper_command(mode, database, extra)
        .output()
        .expect("run helper");
    assert!(
        output.status.success(),
        "helper failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON helper output")
}

fn run_once(database: &Path, worker: &str, now_ms: i64) -> Value {
    let now_ms = now_ms.to_string();
    run_helper(
        "run-once",
        database,
        &[worker, &now_ms, "50", "output-1", "result-hash"],
    )
}

fn inspect(database: &Path, now_ms: i64) -> Value {
    run_helper("inspect", database, &[&now_ms.to_string(), "job-1"])
}

fn assert_completed(run: &Value, winning_fence: i64) {
    assert_eq!(run["barrier"], "completed");
    assert_eq!(run["fence"], winning_fence);
    assert_eq!(run["outcome"], "Committed");
}

fn assert_quiescent(run: &Value) {
    assert_eq!(run["barrier"], "quiescent");
}

fn assert_fresh_oracle(
    inspection: &Value,
    state: &str,
    attempt: i64,
    fence: i64,
    result_count: i64,
    runnable_count: i64,
) {
    assert_eq!(inspection["barrier"], "inspection");
    assert_eq!(inspection["audit"]["integrity_check"], "ok");
    assert_eq!(inspection["audit"]["foreign_key_violations"], 0);
    assert_eq!(inspection["audit"]["job_count"], 1);
    assert_eq!(inspection["audit"]["result_count"], result_count);
    assert_eq!(inspection["audit"]["runnable_job_count"], runnable_count);
    assert_eq!(inspection["job"]["state"], state);
    assert_eq!(inspection["job"]["attempt"], attempt);
    assert_eq!(inspection["job"]["fence"], fence);
    assert_eq!(inspection["pragmas"]["journal_mode"], "wal");
    assert_eq!(inspection["pragmas"]["synchronous"], 2);
    assert_eq!(inspection["pragmas"]["foreign_keys"], true);
    assert_eq!(inspection["pragmas"]["fullfsync"], true);
    assert_eq!(inspection["pragmas"]["checkpoint_fullfsync"], true);
    assert_eq!(inspection["pragmas"]["trusted_schema"], false);
}

fn assert_single_winning_result(inspection: &Value, winning_owner: &str, winning_fence: i64) {
    assert_eq!(inspection["result"]["result_hash"], "result-hash");
    assert_eq!(inspection["result"]["output_key"], "output-1");
    assert_eq!(inspection["result"]["winning_owner"], winning_owner);
    assert_eq!(inspection["result"]["winning_fence"], winning_fence);
}

fn emit_database_evidence(
    test: &str,
    scenario: &str,
    database: &Path,
    inspection: &Value,
    kill_signal: i32,
) {
    let record = json!({
        "test": test,
        "scenario": scenario,
        "status": "pass",
        "database": "sqlite",
        "journal_mode": inspection["pragmas"]["journal_mode"],
        "synchronous": inspection["pragmas"]["synchronous"],
        "integrity_check": inspection["audit"]["integrity_check"],
        "foreign_key_violations": inspection["audit"]["foreign_key_violations"],
        "result_count": inspection["audit"]["result_count"],
        "winning_owner": inspection["result"]["winning_owner"],
        "winning_fence": inspection["result"]["winning_fence"],
        "recovery_process": if kill_signal == libc::SIGKILL { "sigkill" } else { "unexpected" },
        "fresh_process_oracle": database.is_file()
    });
    println!(
        "P00_JOB_EVIDENCE {}",
        serde_json::to_string(&record).unwrap()
    );
}

#[test]
fn sigkill_after_committed_lease_recovers_at_exact_expiry_once() {
    let (_directory, database, store) = fixture();
    let (helper, barrier) = spawn_barrier(helper_command(
        "claim-hang",
        &database,
        &["worker-a", "100", "50"],
    ));
    assert_eq!(barrier["barrier"], "lease_committed");
    assert_eq!(barrier["lease_expires_at_ms"], 150);

    let independently_read = store.job("job-1").unwrap().unwrap();
    assert_eq!(independently_read.state, "running");
    assert_eq!(
        (independently_read.attempt, independently_read.fence),
        (1, 1)
    );
    let kill_signal = helper.kill_group_and_wait();

    assert_quiescent(&run_once(&database, "too-early", 149));
    assert_completed(&run_once(&database, "worker-b", 150), 2);

    let inspection = inspect(&database, 1_000);
    assert_fresh_oracle(&inspection, "succeeded", 2, 2, 1, 0);
    assert_single_winning_result(&inspection, "worker-b", 2);
    assert_quiescent(&run_once(&database, "final-quiescence", 1_000));
    emit_database_evidence(
        "sigkill_after_committed_lease_recovers_at_exact_expiry_once",
        "committed_lease_exact_expiry_recovery",
        &database,
        &inspection,
        kill_signal,
    );
}

#[test]
fn sigkill_before_claim_commit_rolls_back_attempt_and_fence() {
    let (_directory, database, _store) = fixture();
    let (helper, barrier) = spawn_barrier(helper_command(
        "claim-before-commit-hang",
        &database,
        &["worker-a", "100", "50"],
    ));
    assert_eq!(barrier["barrier"], "lease_written_precommit");
    let kill_signal = helper.kill_group_and_wait();

    assert_completed(&run_once(&database, "worker-b", 100), 1);

    let inspection = inspect(&database, 1_000);
    assert_fresh_oracle(&inspection, "succeeded", 1, 1, 1, 0);
    assert_single_winning_result(&inspection, "worker-b", 1);
    assert_quiescent(&run_once(&database, "final-quiescence", 1_000));
    emit_database_evidence(
        "sigkill_before_claim_commit_rolls_back_attempt_and_fence",
        "claim_precommit_rollback",
        &database,
        &inspection,
        kill_signal,
    );
}

#[test]
fn sigkill_after_result_insert_before_commit_rolls_back_output_and_state() {
    let (_directory, database, _store) = fixture();
    let (helper, barrier) = spawn_barrier(helper_command(
        "complete-before-commit-hang",
        &database,
        &["worker-a", "100", "50", "output-1", "result-hash"],
    ));
    assert_eq!(barrier["barrier"], "result_inserted_precommit");
    let kill_signal = helper.kill_group_and_wait();

    let after_crash = inspect(&database, 149);
    assert_fresh_oracle(&after_crash, "running", 1, 1, 0, 0);
    assert!(after_crash["result"].is_null());

    assert_completed(&run_once(&database, "worker-b", 150), 2);
    let inspection = inspect(&database, 1_000);
    assert_fresh_oracle(&inspection, "succeeded", 2, 2, 1, 0);
    assert_single_winning_result(&inspection, "worker-b", 2);
    assert_quiescent(&run_once(&database, "final-quiescence", 1_000));
    emit_database_evidence(
        "sigkill_after_result_insert_before_commit_rolls_back_output_and_state",
        "result_insert_precommit_rollback",
        &database,
        &inspection,
        kill_signal,
    );
}

#[test]
fn sigkill_after_completion_commit_does_not_rerun_or_duplicate_output() {
    let (_directory, database, _store) = fixture();
    let (helper, barrier) = spawn_barrier(helper_command(
        "complete-after-commit-hang",
        &database,
        &["worker-a", "100", "50", "output-1", "result-hash"],
    ));
    assert_eq!(barrier["barrier"], "result_committed");
    let kill_signal = helper.kill_group_and_wait();

    assert_quiescent(&run_once(&database, "worker-b", 1_000));
    let inspection = inspect(&database, 1_000);
    assert_fresh_oracle(&inspection, "succeeded", 1, 1, 1, 0);
    assert_single_winning_result(&inspection, "worker-a", 1);
    assert_quiescent(&run_once(&database, "final-quiescence", 1_001));
    emit_database_evidence(
        "sigkill_after_completion_commit_does_not_rerun_or_duplicate_output",
        "completion_postcommit_no_rerun",
        &database,
        &inspection,
        kill_signal,
    );
}

#[test]
fn reassigned_job_rejects_stale_fence_without_suppressing_winner() {
    let (_directory, database, store) = fixture();
    let stale = store.claim("worker-a", 100, 50).unwrap().unwrap();
    let winner = store.claim("worker-b", 150, 50).unwrap().unwrap();

    assert!(matches!(
        store.complete(&stale, 151, &output("worker-a")),
        Err(StoreError::LeaseLost)
    ));
    assert_eq!(
        store.complete(&winner, 151, &output("worker-b")).unwrap(),
        CompletionOutcome::Committed
    );
    assert_eq!(
        store.complete(&winner, 152, &output("worker-b")).unwrap(),
        CompletionOutcome::AlreadyCommitted
    );

    let mut conflicting_output = output("worker-b");
    conflicting_output.result_hash = "different-result-hash".into();
    assert!(matches!(
        store.complete(&winner, 152, &conflicting_output),
        Err(StoreError::Conflict(_))
    ));
    assert!(matches!(
        store.complete(&stale, 152, &output("worker-a")),
        Err(StoreError::LeaseLost)
    ));

    let mut fabricated_owner = winner.clone();
    fabricated_owner.lease_owner = "fabricated".into();
    assert!(matches!(
        store.complete(&fabricated_owner, 152, &output("worker-b")),
        Err(StoreError::LeaseLost)
    ));
    let mut fabricated_fence = winner.clone();
    fabricated_fence.fence += 1;
    assert!(matches!(
        store.complete(&fabricated_fence, 152, &output("worker-b")),
        Err(StoreError::LeaseLost)
    ));

    let inspection = inspect(&database, 1_000);
    assert_fresh_oracle(&inspection, "succeeded", 2, 2, 1, 0);
    assert_single_winning_result(&inspection, "worker-b", 2);
    assert_quiescent(&run_once(&database, "final-quiescence", 1_000));
    let record = json!({
        "test": "reassigned_job_rejects_stale_fence_without_suppressing_winner",
        "scenario": "stale_and_fabricated_lease_rejection",
        "status": "pass",
        "database": "sqlite",
        "journal_mode": inspection["pragmas"]["journal_mode"],
        "synchronous": inspection["pragmas"]["synchronous"],
        "integrity_check": inspection["audit"]["integrity_check"],
        "foreign_key_violations": inspection["audit"]["foreign_key_violations"],
        "result_count": inspection["audit"]["result_count"],
        "winning_owner": inspection["result"]["winning_owner"],
        "winning_fence": inspection["result"]["winning_fence"],
        "fresh_process_oracle": database.is_file(),
        "stale_fence_rejected": true,
        "fabricated_owner_rejected": true,
        "fabricated_fence_rejected": true
    });
    println!(
        "P00_JOB_EVIDENCE {}",
        serde_json::to_string(&record).unwrap()
    );
}

#[test]
fn timeout_cleanup_kills_and_reaps_the_complete_process_group() {
    let unrelated_database_argument = Path::new("unused");
    let (mut helper, barrier) = spawn_barrier(helper_command(
        "hang-with-descendant",
        unrelated_database_argument,
        &[],
    ));
    assert_eq!(barrier["barrier"], "descendant_started");
    let helper_pid = barrier["helper_pid"].as_i64().unwrap() as i32;
    let descendant_pid = barrier["descendant_pid"].as_i64().unwrap() as i32;
    assert_eq!(helper.process_group, helper_pid);

    let timeout = Instant::now() + Duration::from_millis(50);
    while Instant::now() < timeout {
        assert!(helper
            .child
            .as_mut()
            .expect("armed helper")
            .try_wait()
            .unwrap()
            .is_none());
        thread::sleep(Duration::from_millis(5));
    }
    assert!(helper
        .child
        .as_mut()
        .expect("armed helper")
        .try_wait()
        .unwrap()
        .is_none());
    let kill_signal = helper.kill_group_and_wait();

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && process_exists(descendant_pid) {
        thread::sleep(Duration::from_millis(10));
    }
    let helper_terminated = !process_exists(helper_pid);
    let descendant_terminated = !process_exists(descendant_pid);
    assert!(helper_terminated);
    assert!(descendant_terminated);
    assert_eq!(kill_signal, libc::SIGKILL);

    let (armed_guard, guarded_barrier) = spawn_barrier(helper_command(
        "hang-with-descendant",
        unrelated_database_argument,
        &[],
    ));
    let guarded_helper_pid = guarded_barrier["helper_pid"].as_i64().unwrap() as i32;
    let guarded_descendant_pid = guarded_barrier["descendant_pid"].as_i64().unwrap() as i32;
    drop(armed_guard);
    wait_until_process_exits(guarded_descendant_pid);
    let guarded_helper_terminated = !process_exists(guarded_helper_pid);
    let guarded_descendant_terminated = !process_exists(guarded_descendant_pid);
    assert!(guarded_helper_terminated);
    assert!(guarded_descendant_terminated);

    let record = json!({
        "test": "timeout_cleanup_kills_and_reaps_the_complete_process_group",
        "scenario": "timeout_process_group_cleanup",
        "status": "pass",
        "recovery_process": if kill_signal == libc::SIGKILL { "sigkill" } else { "unexpected" },
        "process_tree_cleanup": helper_terminated
            && descendant_terminated
            && guarded_helper_terminated
            && guarded_descendant_terminated
    });
    println!(
        "P00_JOB_EVIDENCE {}",
        serde_json::to_string(&record).unwrap()
    );
}

fn process_exists(pid: i32) -> bool {
    let result = unsafe { libc::kill(pid, 0) };
    if result == 0 {
        true
    } else {
        std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }
}

fn wait_until_process_exits(pid: i32) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && process_exists(pid) {
        thread::sleep(Duration::from_millis(10));
    }
}
