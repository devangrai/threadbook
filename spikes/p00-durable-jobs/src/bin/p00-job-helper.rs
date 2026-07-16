use p00_durable_jobs::{JobOutput, JobStore};
use serde_json::json;
use std::env;
use std::io::{self, Write};
use std::process::{self, Command};
use std::thread;

fn main() {
    if let Err(error) = run() {
        let _ = emit(json!({"error": error}));
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<String> = env::args().collect();
    let mode = argument(&arguments, 1, "mode")?;

    if mode == "hang-with-descendant" {
        let child = Command::new("sleep")
            .arg("300")
            .spawn()
            .map_err(|error| format!("spawn descendant: {error}"))?;
        emit(json!({
            "barrier": "descendant_started",
            "helper_pid": process::id(),
            "descendant_pid": child.id()
        }))?;
        hang();
    }

    let database = argument(&arguments, 2, "database path")?;
    let store = JobStore::open(database).map_err(|error| error.to_string())?;

    match mode {
        "claim-before-commit-hang" => {
            let worker = argument(&arguments, 3, "worker")?;
            let now_ms = integer_argument(&arguments, 4, "now_ms")?;
            let lease_ms = integer_argument(&arguments, 5, "lease_ms")?;
            store
                .claim_with_observer(worker, now_ms, lease_ms, |lease| {
                    emit(json!({
                        "barrier": "lease_written_precommit",
                        "job_id": lease.job.id,
                        "attempt": lease.attempt,
                        "fence": lease.fence
                    }))
                    .expect("emit claim barrier");
                    hang();
                })
                .map_err(|error| error.to_string())?;
        }
        "claim-hang" => {
            let worker = argument(&arguments, 3, "worker")?;
            let now_ms = integer_argument(&arguments, 4, "now_ms")?;
            let lease_ms = integer_argument(&arguments, 5, "lease_ms")?;
            let lease = store
                .claim(worker, now_ms, lease_ms)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "no runnable job".to_string())?;
            emit(json!({
                "barrier": "lease_committed",
                "job_id": lease.job.id,
                "attempt": lease.attempt,
                "fence": lease.fence,
                "lease_expires_at_ms": lease.lease_expires_at_ms
            }))?;
            hang();
        }
        "complete-before-commit-hang" => {
            let (worker, now_ms, lease_ms, output) = completion_arguments(&arguments)?;
            let lease = store
                .claim(worker, now_ms, lease_ms)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "no runnable job".to_string())?;
            store
                .complete_with_observer(&lease, now_ms, &output, |_| {
                    emit(json!({
                        "barrier": "result_inserted_precommit",
                        "job_id": lease.job.id,
                        "fence": lease.fence
                    }))
                    .expect("emit completion barrier");
                    hang();
                })
                .map_err(|error| error.to_string())?;
        }
        "complete-after-commit-hang" => {
            let (worker, now_ms, lease_ms, output) = completion_arguments(&arguments)?;
            let lease = store
                .claim(worker, now_ms, lease_ms)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "no runnable job".to_string())?;
            let outcome = store
                .complete(&lease, now_ms, &output)
                .map_err(|error| error.to_string())?;
            emit(json!({
                "barrier": "result_committed",
                "job_id": lease.job.id,
                "fence": lease.fence,
                "outcome": format!("{outcome:?}")
            }))?;
            hang();
        }
        "run-once" => {
            let (worker, now_ms, lease_ms, output) = completion_arguments(&arguments)?;
            let Some(lease) = store
                .claim(worker, now_ms, lease_ms)
                .map_err(|error| error.to_string())?
            else {
                emit(json!({"barrier": "quiescent"}))?;
                return Ok(());
            };
            let outcome = store
                .complete(&lease, now_ms, &output)
                .map_err(|error| error.to_string())?;
            emit(json!({
                "barrier": "completed",
                "job_id": lease.job.id,
                "fence": lease.fence,
                "outcome": format!("{outcome:?}")
            }))?;
        }
        "inspect" => {
            let now_ms = integer_argument(&arguments, 3, "now_ms")?;
            let job_id = argument(&arguments, 4, "job_id")?;
            emit(json!({
                "barrier": "inspection",
                "audit": store.audit(now_ms).map_err(|error| error.to_string())?,
                "job": store.job(job_id).map_err(|error| error.to_string())?,
                "result": store.result(job_id).map_err(|error| error.to_string())?,
                "pragmas": store.pragmas().map_err(|error| error.to_string())?
            }))?;
        }
        other => return Err(format!("unknown mode: {other}")),
    }
    Ok(())
}

fn completion_arguments(arguments: &[String]) -> Result<(&str, i64, i64, JobOutput), String> {
    Ok((
        argument(arguments, 3, "worker")?,
        integer_argument(arguments, 4, "now_ms")?,
        integer_argument(arguments, 5, "lease_ms")?,
        JobOutput {
            output_key: argument(arguments, 6, "output_key")?.to_string(),
            result_hash: argument(arguments, 7, "result_hash")?.to_string(),
            output: json!({"produced_by": argument(arguments, 3, "worker")?}),
        },
    ))
}

fn argument<'a>(arguments: &'a [String], index: usize, name: &str) -> Result<&'a str, String> {
    arguments
        .get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("missing {name}"))
}

fn integer_argument(arguments: &[String], index: usize, name: &str) -> Result<i64, String> {
    argument(arguments, index, name)?
        .parse()
        .map_err(|error| format!("invalid {name}: {error}"))
}

fn emit(value: serde_json::Value) -> Result<(), String> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &value).map_err(|error| error.to_string())?;
    stdout
        .write_all(b"\n")
        .and_then(|()| stdout.flush())
        .map_err(|error| error.to_string())
}

fn hang() -> ! {
    loop {
        thread::park();
    }
}
