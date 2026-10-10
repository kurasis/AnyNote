import { readFile } from 'node:fs/promises';

const METHOD='25ms timer; serialized CDP process enumeration + Linux /proc aggregate RSS at irregular actual cadence; shared pages may count twice; transient peaks may be missed; desktop only';
export async function sampleRss(cdp) {
  if (process.platform !== 'linux') return null;
  const { processInfo } = await cdp.send('SystemInfo.getProcessInfo');
  let total=0, sampled=0;
  for (const info of processInfo) {
    try {
      const match=/^VmRSS:\s+(\d+)\s+kB/m.exec(await readFile(`/proc/${info.id}/status`,'utf8'));
      if (match) { total+=Number(match[1]); sampled++; }
    } catch {} // A process may exit between enumeration and sampling.
  }
  return sampled ? total : null;
}

export async function beginRssSample(cdp) {
  const baseline=await sampleRss(cdp),started=performance.now();
  let peak=baseline,samples=baseline===null?0:1,errors=0,inFlight,lastSampleAt=started,longestGap=0;
  async function sample() {
    try {
      const value=await sampleRss(cdp);
      if(value!==null){
        const now=performance.now();longestGap=Math.max(longestGap,now-lastSampleAt);lastSampleAt=now;
        peak=Math.max(peak??0,value);samples++;
      }
    } catch { errors++; }
  }
  const interval=setInterval(()=>{
    if(inFlight)return;
    inFlight=sample().finally(()=>{inFlight=null;});
  },25);
  return async()=>{
    clearInterval(interval);
    await inFlight; // Never let an old phase sampler overlap the next trial.
    await sample();
    return {status:baseline===null?'UNAVAILABLE':'MEASURED',
      baseline_aggregate_rss_kib:baseline,sampled_peak_aggregate_rss_kib:peak,
      sampled_increment_rss_kib:baseline===null||peak===null?null:peak-baseline,
      samples,sampling_errors:errors,requested_interval_ms:25,longest_observed_sample_gap_ms:Math.round(longestGap),
      elapsed_ms:Math.round(performance.now()-started),method:METHOD};
  };
}
