// Actual Linux process counters. Do not read command lines, environment, paths
// or memory contents; peers and shared-page double counts remain explicit.
import {readdirSync, readFileSync} from 'node:fs';

const counter = (raw, name) => {
  const value = new RegExp('^' + name + ':\\s+(\\d+) kB$', 'm').exec(raw);
  return value ? Number(value[1]) * 1024 : null;
};

export function processMemory() {
  const started = performance.now(), records = new Map();
  let samples = 0, initial = true, baseline = null, peak = 0, last = null, largestGap = 0;
  const sample = () => {
    const now = Math.round(performance.now() - started);
    if (last !== null) largestGap = Math.max(largestGap, now - last);
    last = now; samples++;
    let total = 0, count = 0;
    for (const pid of readdirSync('/proc')) {
      if (!/^[0-9]+$/.test(pid)) continue;
      try {
        const name = readFileSync('/proc/' + pid + '/comm', 'utf8').trim();
        if (!/^(chrome|chromium|chrome_crashpad)$/.test(name)) continue;
        const status = readFileSync('/proc/' + pid + '/status', 'utf8');
        const rss = counter(status, 'VmRSS'); if (rss === null) continue;
        const stat = readFileSync('/proc/' + pid + '/stat', 'utf8');
        const startTicks = stat.slice(stat.lastIndexOf(')') + 2).split(' ')[19];
        let rollup = '';
        try { rollup = readFileSync('/proc/' + pid + '/smaps_rollup', 'utf8'); } catch {}
        const value = {rss, anonymous_rss: counter(status, 'RssAnon'),
          file_rss: counter(status, 'RssFile'), shared_memory_rss: counter(status, 'RssShmem'),
          proportional_set: counter(rollup, 'Pss')};
        const key = pid + ':' + startTicks;
        if (!records.has(key)) records.set(key, {pid: Number(pid), process_name: name,
          present_at_phase_start: initial, baseline_bytes: {...value}, first_observed_bytes: {...value},
          observed_peak_bytes: {...value}, first_observed_ms: now, last_observed_ms: now, samples: 0});
        const record = records.get(key); record.samples++; record.last_observed_ms = now;
        for (const metric of Object.keys(value)) if (value[metric] !== null) record.observed_peak_bytes[metric] = Math.max(record.observed_peak_bytes[metric] ?? 0, value[metric]);
        total += rss; count++;
      } catch {}
    }
    if (initial) baseline = count ? total : null;
    initial = false; peak = Math.max(peak, total);
  };
  sample(); const timer = setInterval(sample, 1000);
  return {
    finish() {
      clearInterval(timer); sample();
      if (!baseline || records.size === 0) throw Error('PROCESS_MEMORY_NOT_MEASURED');
      return {requested_sample_interval_ms: 1000, samples, largest_observed_gap_ms: largestGap,
        baseline_rss_bytes: baseline, observed_peak_rss_bytes: peak,
        observed_peak_growth_bytes: Math.max(0, peak - baseline),
        processes: [...records.values()].map(record => ({...record,
          observed_growth_from_first_sample_bytes: Object.fromEntries(Object.keys(record.baseline_bytes).map(key => [key,
            record.baseline_bytes[key] === null ? null : Math.max(0, record.observed_peak_bytes[key] - record.baseline_bytes[key])])),
        })),
        scope: 'All Chrome-family processes on this isolated Linux job, including peer test browsers. RSS double-counts shared mappings; file/anonymous/shared/PSS counters are separate and unavailable counters remain null. New processes have their own first-observed baseline; aggregate phase peak is a simultaneous sum, not a sum of individual peaks. Node offline reader is excluded. No physical iPhone or unsampled maximum claim.'};
    },
    abort() { clearInterval(timer); },
  };
}
