//! Bounded native jobs. No paths, plaintext names or secrets in progress/errors.
use crate::*;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};
pub struct Job {
    pub id: String,
    pub generation: u64,
    cancel: AtomicBool,
    bytes: AtomicU64,
    total: AtomicU64,
    state: Mutex<String>,
    error: Mutex<Option<&'static str>>,
    result: Mutex<Option<Value>>,
    created: Instant,
}
impl Job {
    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }
    pub fn check(&self, current: u64) -> Result<()> {
        check(
            self.generation == current && !self.cancel.load(Ordering::SeqCst),
            "RESUME_REQUIRED",
        )
    }
    pub fn progress(&self, bytes: u64, total: u64) {
        self.bytes.store(bytes, Ordering::SeqCst);
        self.total.store(total, Ordering::SeqCst);
    }
    pub fn finish(&self, result: Result<Value>) {
        match result {
            Ok(result) => {
                *self.result.lock().unwrap() = Some(result);
                *self.state.lock().unwrap() = "COMPLETE".into();
            }
            Err(e) => {
                *self.state.lock().unwrap() = if self.cancel.load(Ordering::SeqCst) {
                    "PAUSED"
                } else {
                    "NEEDS_ATTENTION"
                }
                .into();
                *self.error.lock().unwrap() = Some(e.0);
            }
        }
    }
    fn public(&self) -> Value {
        serde_json::json!({"job_id":self.id,"generation":self.generation,"state":self.state.lock().unwrap().as_str(),"bytes":self.bytes.load(Ordering::SeqCst).to_string(),"total":self.total.load(Ordering::SeqCst).to_string(),"error":*self.error.lock().unwrap(),"result":self.result.lock().unwrap().clone(),"elapsed_ms":self.created.elapsed().as_millis().to_string()})
    }
}
#[derive(Default)]
pub struct Jobs {
    rows: Mutex<BTreeMap<String, Arc<Job>>>,
}
impl Jobs {
    pub fn start(&self, generation: u64) -> Result<Arc<Job>> {
        let mut rows = self.rows.lock().map_err(|_| Error("HOST_BUSY"))?;
        check(
            rows.values()
                .filter(|j| *j.state.lock().unwrap() == "RUNNING")
                .count()
                < 2,
            "HOST_BUSY",
        )?;
        if rows.len() >= 64 {
            let expired = rows
                .iter()
                .find(|(_, j)| *j.state.lock().unwrap() != "RUNNING")
                .map(|(id, _)| id.clone())
                .ok_or(Error("RESOURCE_LIMIT"))?;
            rows.remove(&expired);
        }
        let job = Arc::new(Job {
            id: random_id(),
            generation,
            cancel: AtomicBool::new(false),
            bytes: AtomicU64::new(0),
            total: AtomicU64::new(0),
            state: Mutex::new("RUNNING".into()),
            error: Mutex::new(None),
            result: Mutex::new(None),
            created: Instant::now(),
        });
        rows.insert(job.id.clone(), job.clone());
        Ok(job)
    }
    pub fn cancel(&self, id: &str) -> Result<()> {
        let rows = self.rows.lock().map_err(|_| Error("HOST_BUSY"))?;
        rows.get(id)
            .ok_or(Error("NOT_FOUND"))?
            .cancel
            .store(true, Ordering::SeqCst);
        Ok(())
    }
    pub fn pause_all(&self) {
        if let Ok(rows) = self.rows.lock() {
            for j in rows.values() {
                j.cancel.store(true, Ordering::SeqCst);
            }
        }
    }
    pub fn summary(&self, g: u64) -> Result<Value> {
        Ok(
            serde_json::json!({"items":self.rows.lock().map_err(|_|Error("HOST_BUSY"))?.values().filter(|j|j.generation==g).map(|j|j.public()).collect::<Vec<_>>()}),
        )
    }
}
