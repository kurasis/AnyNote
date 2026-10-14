// Actual hosted Chromium process RSS, public byte counts only; shared pages may be counted twice.
import {readdirSync,readFileSync} from 'node:fs';
export function browserMemory(){
 const read=()=>{let total=0;for(const pid of readdirSync('/proc')){if(!/^[0-9]+$/.test(pid))continue;try{const name=readFileSync('/proc/'+pid+'/comm','utf8').trim();if(!/^(chrome|chromium|chrome_crashpad)$/.test(name))continue;const status=readFileSync('/proc/'+pid+'/status','utf8'),rss=/^VmRSS:\s+(\d+) kB/m.exec(status);if(rss)total+=Number(rss[1])*1024;}catch{}}return total;};
 const baseline=read();let peak=baseline,count=0;const timer=setInterval(()=>{peak=Math.max(peak,read());count++;},250);
 return {finish(){clearInterval(timer);if(!baseline||!count)throw Error('BROWSER_MEMORY_NOT_SAMPLED');return {samples:count,sample_interval_ms:250,baseline_rss_bytes:baseline,observed_peak_rss_bytes:peak,observed_peak_growth_bytes:Math.max(0,peak-baseline),scope:'sum of actual hosted Chromium process RSS; includes shared-page double counts and other open fixture windows; no iPhone or hard memory ceiling claim'};},abort(){clearInterval(timer);}};
}
