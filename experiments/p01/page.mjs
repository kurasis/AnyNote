// Test runner entry, not a user-facing application or preview.
const worker = new Worker('/worker.js', { type: 'module' });
let pending;
worker.onmessage = ({ data }) => {
  if (data.kind === 'progress') { globalThis.p01Progress = data; return; }
  if (!pending) return;
  const { resolve, reject } = pending; pending = null;
  if (data.kind === 'error') reject(new Error(data.message)); else resolve(data);
};
worker.onerror = (event) => { if (pending) { pending.reject(new Error(event.message)); pending = null; } };
globalThis.p01 = (data) => new Promise((resolve, reject) => {
  if (pending) { reject(new Error('Experiment already running')); return; }
  pending = { resolve, reject }; worker.postMessage(data);
});
