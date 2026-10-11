#!/usr/bin/env python3
"""Install only checksum-pinned public upstream CLI artifacts into ignored storage."""
import hashlib,json,os,platform,subprocess,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    if platform.system()!='Linux' or platform.machine() not in ('x86_64','AMD64'):raise RuntimeError('Synthetic tool installer supports Linux amd64 only; native product builds belong to P05/P13')
    output=ROOT/'.local/p02-tools';output.mkdir(parents=True,exist_ok=True)
    for artifact in json.loads((ROOT/'packages/contracts/p02-export-tools.json').read_text())['artifacts']:
        archive=output/(artifact['name']+'-'+artifact['version']+'.tar.gz')
        if not archive.exists():subprocess.run(['curl','--fail','--silent','--show-error','--location','--proto','=https','--tlsv1.2',artifact['url'],'--output',str(archive)],check=True)
        if hashlib.sha256(archive.read_bytes()).hexdigest()!=artifact['digest_hex']:raise RuntimeError('Upstream artifact checksum mismatch')
        with tarfile.open(archive,'r:gz') as tar:
            for member,target in artifact['members'].items():
                item=tar.getmember(member)
                if not item.isfile() or item.size>50000000:raise RuntimeError('Unsafe upstream executable member')
                with tar.extractfile(item) as source:data=source.read()
                dest=output/target;dest.write_bytes(data);dest.chmod(0o755)
        version=subprocess.check_output([str(output/artifact['name']),'--version'],text=True,env={**os.environ,'LANG':'en_US.UTF-8'}).strip()
        assert artifact['version'] in version,version
    print('PASS: checksum-pinned Rust rage 0.12.1 and independent Go age 1.3.2')
if __name__=='__main__':main()
