// CDP reports V8 heap/backing storage separately from OS working sets. It does
// not establish WebKit/iPhone memory use or a hard upper bound between samples.
export async function browserHeap(page) {
  const cdp = await page.context().newCDPSession(page);
  const started = performance.now();
  const workers = new Map(), pending = new Map(), records = new Map();
  let sequence = 0, rendererEpoch = 0, busy = false, stopped = false;
  cdp.on('Runtime.executionContextsCleared', () => { rendererEpoch++; });
  await cdp.send('Runtime.enable');
  cdp.on('Target.attachedToTarget', ({sessionId, targetInfo}) => {
    if (targetInfo.type === 'worker') workers.set(sessionId, true);
  });
  cdp.on('Target.detachedFromTarget', ({sessionId}) => workers.delete(sessionId));
  cdp.on('Target.receivedMessageFromTarget', ({sessionId, message}) => {
    const value = JSON.parse(message), key = sessionId + ':' + value.id;
    const entry = pending.get(key);
    if (!entry) return;
    pending.delete(key); clearTimeout(entry.timer);
    value.error ? entry.reject(Error('HEAP_CDP_ERROR')) : entry.resolve(value.result);
  });
  await cdp.send('Target.setAutoAttach', {autoAttach: true, waitForDebuggerOnStart: false, flatten: false});
  const record = (key, value) => {
    if (!value || !Number.isFinite(value.usedSize) || !Number.isFinite(value.totalSize)) return;
    const bytes = {used_heap: value.usedSize, allocated_heap: value.totalSize,
      backing_storage: value.backingStorageSize ?? null, embedder_heap: value.embedderHeapUsedSize ?? null};
    let current = records.get(key);
    if (!current) {
      current = {role: key.startsWith('renderer:') ? 'renderer' : 'dedicated-worker', baseline_bytes: bytes, observed_peak_bytes: {...bytes}, samples: 0,
        first_observed_ms: Math.round(performance.now() - started), last_observed_ms: null, largest_observed_gap_ms: 0};
      records.set(key, current);
    }
    const observed = Math.round(performance.now() - started);
    if (current.last_observed_ms !== null) current.largest_observed_gap_ms = Math.max(current.largest_observed_gap_ms, observed - current.last_observed_ms);
    current.last_observed_ms = observed; current.samples++;
    for (const name of Object.keys(bytes)) if (bytes[name] !== null) current.observed_peak_bytes[name] = Math.max(current.observed_peak_bytes[name] ?? 0, bytes[name]);
  };
  const workerSample = sessionId => new Promise((resolve, reject) => {
    const id = ++sequence, key = sessionId + ':' + id;
    const timer = setTimeout(() => { pending.delete(key); reject(Error('HEAP_SAMPLE_TIMEOUT')); }, 2000);
    pending.set(key, {resolve, reject, timer});
    cdp.send('Target.sendMessageToTarget', {sessionId, message: JSON.stringify({id, method: 'Runtime.getHeapUsage'})}).catch(() => {
      pending.delete(key); clearTimeout(timer); reject(Error('HEAP_WORKER_ENDED'));
    });
  });
  const sample = async () => {
    if (busy || stopped) return;
    busy = true;
    try {
      await Promise.all([
        cdp.send('Runtime.getHeapUsage').then(value => record('renderer:' + rendererEpoch, value)).catch(() => {}),
        ...[...workers.keys()].map(id => workerSample(id).then(value => record(id, value)).catch(() => {})),
      ]);
    } finally { busy = false; }
  };
  await sample();
  const timer = setInterval(sample, 1000);
  return {
    async finish() {
      clearInterval(timer); await sample(); stopped = true;
      await cdp.detach();
      const agents = [...records.values()].map(value => ({...value,
        observed_growth_bytes: Object.fromEntries(Object.keys(value.baseline_bytes).map(key => [key,
          value.baseline_bytes[key] === null ? null : Math.max(0, value.observed_peak_bytes[key] - value.baseline_bytes[key])])),
      }));
      if (!agents.some(a => a.role === 'dedicated-worker' && a.samples > 1)) throw Error('WORKER_HEAP_NOT_MEASURED');
      return {requested_sample_interval_ms: 1000, agents,
        scope: 'V8 Runtime.getHeapUsage for this hosted Chromium renderer and related dedicated Workers; receipt times record observed cadence, agents restart after lock/navigation, shared/external/WASM/native memory and between-sample peaks may lie outside these counters; not iPhone/WebKit memory evidence'};
    },
    async abort() {
      clearInterval(timer); stopped = true;
      for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(Error('HEAP_STOPPED')); }
      pending.clear(); await cdp.detach().catch(() => {});
    },
  };
}
