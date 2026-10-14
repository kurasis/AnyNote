#!/usr/bin/env python3
"""Prepare the pinned trusted helper for the single installer; never execute downloads."""
import base64,hashlib,json,urllib.request,zipfile,io
from pathlib import Path
root=Path(__file__).resolve().parent/'src-tauri/resources';root.mkdir(parents=True,exist_ok=True)
url='https://nodejs.org/dist/v24.21.0/node-v24.21.0-win-x64.zip'
expected='158f7685b44de51f6c0df1d153526cbcd3e1bc739a8dfc607721cef75de9e541'
data=urllib.request.urlopen(url,timeout=60).read()
assert hashlib.sha256(data).hexdigest()==expected,'Official runtime hash mismatch'
with zipfile.ZipFile(io.BytesIO(data)) as z:
    for name,target in [('node.exe','node.exe'),('LICENSE','NODE-LICENSE')]:
        (root/target).write_bytes(z.read('node-v24.21.0-win-x64/'+name))
sha=lambda b:base64.urlsafe_b64encode(hashlib.sha256(b).digest()).decode().rstrip('=')
manifest={'version':1,'node_sha256':sha((root/'node.exe').read_bytes()),'script_sha256':sha((root/'custody.mjs').read_bytes()),'provenance':{'url':url,'archive_sha256':expected,'node':'24.21.0','license':'Installed NODE-LICENSE includes bundled components'}}
(root/'runtime-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('PASS: official pinned Node runtime and license prepared for one installer')
