#!/usr/bin/env python3
"""Freeze conservative dependency provenance and stage upstream license texts for the Windows installer."""
import argparse,base64,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'apps/desktop';RES=APP/'src-tauri/resources';INVENTORY=APP/'dependency-inventory.json'
LOCKS=['apps/desktop/src-tauri/Cargo.lock','packages/windows-native/Cargo.lock','apps/desktop/package-lock.json','packages/protocol/package-lock.json','packages/content-browser/package-lock.json']
LICENSE=re.compile(r'^(?:licen[cs]e|copying|copyright|notice)(?:[._-].*)?$',re.I)
def sha(data):return hashlib.sha256(data).hexdigest()
def metadata(manifest):
    return json.loads(subprocess.check_output(['cargo','metadata','--manifest-path',str(ROOT/manifest),'--format-version','1','--locked','--all-features','--filter-platform','x86_64-pc-windows-msvc'],cwd=ROOT))
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def build():
    import tomllib
    components={};license_sources=[]
    for manifest,lock in [('apps/desktop/src-tauri/Cargo.toml',LOCKS[0]),('packages/windows-native/Cargo.toml',LOCKS[1])]:
        data=metadata(manifest);pins={(p['name'],p['version'],p.get('source')):p for p in tomllib.loads((ROOT/lock).read_text(encoding='utf-8'))['package']}
        for package in data['packages']:
            if not package['source']:continue
            pin=pins[(package['name'],package['version'],package['source'])]
            key='pkg:cargo/'+package['name']+'@'+package['version']
            components[key]={'purl':key,'ecosystem':'cargo','name':package['name'],'version':package['version'],'source':package['source'],'sha256':pin['checksum'],'license':package['license'],'scope':'Conservative frozen Cargo metadata closure including unused targets and build/test features; not an exact linked-code census'}
            license_sources.append((key,Path(package['manifest_path']).parent))
    for name in LOCKS[2:]:
        lock=json.loads((ROOT/name).read_text(encoding='utf-8'));base=(ROOT/name).parent
        for location,p in lock['packages'].items():
            if not location:continue
            package_name=p.get('name') or location.rsplit('node_modules/',1)[-1]
            key='pkg:npm/'+package_name+'@'+p['version']
            entry={'purl':key,'ecosystem':'npm','name':package_name,'version':p['version'],'source':p.get('resolved'),'integrity':p.get('integrity'),'license':p.get('license'),'scope':'Conservative frozen app/helper/preview dependency set including build and optional platform packages'}
            if key in components:assert components[key]['integrity']==entry['integrity']
            components[key]=entry;license_sources.append((key,base/location))
    components['pkg:generic/node@24.21.0']={'purl':'pkg:generic/node@24.21.0','ecosystem':'official-runtime','name':'Node.js Windows x64','version':'24.21.0','source':'https://nodejs.org/dist/v24.21.0/node-v24.21.0-win-x64.zip','sha256':'158f7685b44de51f6c0df1d153526cbcd3e1bc739a8dfc607721cef75de9e541','license':'MIT AND upstream bundled component notices','scope':'Bundled trusted standard-age helper runtime; complete upstream NODE-LICENSE accompanies installer'}
    report={'purpose':'P14 conservative frozen Windows dependency provenance','version':1,'lockfiles':{name:sha((ROOT/name).read_bytes()) for name in LOCKS},'components':sorted(components.values(),key=lambda p:p['purl']),'limitations':'Includes build/test/optional packages. Archive hashes and upstream license declarations are provenance, not an independent legal or security review.'}
    return report,license_sources

def stage(report,sources):
    # Only generated installer resources are replaced. Never touch profiles, sources or prior locks.
    destination=RES/'licenses';destination.mkdir(parents=True,exist_ok=True)
    index=[];seen=set()
    for purl,base in sources:
        if purl in seen or not base.is_dir():continue
        seen.add(purl)
        target=destination/re.sub('[^A-Za-z0-9._-]','_',purl)
        for item in sorted(base.iterdir()):
            if item.is_file() and LICENSE.match(item.name):
                data=item.read_bytes()
                if len(data)>1048576:raise RuntimeError('Upstream license exceeds conservative notice size: '+purl)
                target.mkdir(exist_ok=True);(target/item.name).write_bytes(data)
                index.append({'component':purl,'file':str((target/item.name).relative_to(RES)).replace('\\','/'),'sha256':sha(data)})
            elif item.is_dir() and item.name.lower()=='licenses':
                for nested in sorted(item.rglob('*')):
                    if not nested.is_file():continue
                    data=nested.read_bytes()
                    if len(data)>1048576:raise RuntimeError('Upstream license file too large')
                    out=target/'LICENSES'/nested.relative_to(item);out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(data);index.append({'component':purl,'file':str(out.relative_to(RES)).replace('\\','/'),'sha256':sha(data)})
    shutil.copyfile(ROOT/'packages/vault-native/LICENSE',RES/'COPYING-GPL-3.0')
    (RES/'dependency-inventory.json').write_text(json.dumps(report,indent=2)+'\n')
    (RES/'license-index.json').write_text(json.dumps({'purpose':'Installer upstream notice files staged from verified package sources','files':index},indent=2)+'\n')
    notices=['AnyNote Windows development candidate — GPL-3.0-only','Corresponding application source: https://github.com/kurasis/AnyNote','The exact source commit is in SOURCE-COMMIT. Reproduce with the frozen locks.','Third-party source archives, checksums and upstream license declarations are in dependency-inventory.json.','Full upstream text files present in installed packages are in licenses/ and NODE-LICENSE.','The inventory conservatively includes build/test/optional dependencies, not all are bundled runtime code.','']
    notices += [p['purl']+' | '+str(p['license'])+' | '+str(p['source']) for p in report['components']]
    (RES/'THIRD-PARTY-NOTICES.txt').write_text('\n'.join(notices)+'\n')
    (RES/'SOURCE-COMMIT').write_bytes(subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT))
    cyclone={'bomFormat':'CycloneDX','specVersion':'1.6','version':1,'metadata':{'component':{'type':'application','name':'AnyNote Windows','version':'0.14.0'}},'components':[]}
    for p in report['components']:
        component={'type':'library','bom-ref':p['purl'],'name':p['name'],'version':p['version'],'purl':p['purl'],'properties':[{'name':'anynote:scope','value':p['scope']},{'name':'anynote:upstream-license-declaration','value':str(p['license'])}]}
        if p.get('sha256'):component['hashes']=[{'alg':'SHA-256','content':p['sha256']}]
        elif p.get('integrity','').startswith('sha512-'):component['hashes']=[{'alg':'SHA-512','content':base64.b64decode(p['integrity'].split('-',1)[1]).hex()}]
        if p.get('source') and p['source'].startswith('https:'):component['externalReferences']=[{'type':'distribution','url':p['source']}]
        cyclone['components'].append(component)
    (RES/'sbom.cdx.json').write_text(json.dumps(cyclone,indent=2)+'\n')
    print('PASS: '+str(len(report['components']))+' frozen conservative components; '+str(len(index))+' upstream license texts staged')

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');parser.add_argument('--stage',action='store_true');a=parser.parse_args()
    report,sources=build()
    if a.write:INVENTORY.write_text(json.dumps(report,indent=2)+'\n')
    else:
        if canonical(json.loads(INVENTORY.read_text(encoding='utf-8')))!=canonical(report):raise RuntimeError('Frozen P14 dependency inventory differs from locked provenance')
    if a.stage:stage(report,sources)
    else:print('PASS: frozen Windows dependency provenance '+str(len(report['components']))+' components')
if __name__=='__main__':main()
