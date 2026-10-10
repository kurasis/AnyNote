// Test runner entry, not a user-facing application or preview.
const worker = new Worker('/worker.js', { type: 'module' });
let pending;
let workerFailure;
function armTimeout() {
  if (!pending) return;
  clearTimeout(pending.timer);
  pending.timer = setTimeout(() => {
    const { reject } = pending; pending = null; worker.terminate();
    workerFailure = new Error('Worker made no progress for 60 seconds');
    reject(workerFailure);
  }, 60000);
}
worker.onmessage = ({ data }) => {
  if (data.kind === 'progress') { globalThis.p01Progress = data; armTimeout(); return; }
  if (!pending) return;
  clearTimeout(pending.timer);
  const { resolve, reject } = pending; pending = null;
  if (data.kind === 'error') reject(new Error(data.message)); else resolve(data);
};
worker.onerror = (event) => {
  workerFailure = new Error(event.message);
  if (pending) { clearTimeout(pending.timer); pending.reject(workerFailure); pending = null; }
};
globalThis.p01 = (data) => new Promise((resolve, reject) => {
  if (workerFailure) { reject(workerFailure); return; }
  if (pending) { reject(new Error('Experiment already running')); return; }
  pending = { resolve, reject }; armTimeout(); worker.postMessage(data);
});
