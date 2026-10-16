#!/usr/bin/env python3
"""Real age/OpenSSL adversarial backup parser tests; no product data/services."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
spec=importlib.util.spec_from_file_location('operations',Path(__file__).with_name('operations.py'));ops=importlib.util.module_from_spec(spec);spec.loader.exec_module(ops)


class Backups(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='anynote-p16-negative-');cls.root=Path(cls.temporary.name);cls.age=ops.ROOT/'.local/p02-tools/age';cls.keygen=ops.ROOT/'.local/p02-tools/age-keygen'
        for name in ['identity','other']:(cls.root/name).write_bytes(ops.run([cls.keygen]))
        cls.recipient=ops.run([cls.keygen,'-y',cls.root/'identity']).decode().strip()
        ops.run(['openssl','genpkey','-algorithm','ED25519','-out',cls.root/'signing'])
        ops.run(['openssl','pkey','-in',cls.root/'signing','-pubout','-out',cls.root/'verification'])

    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()

    def archive(self,entries=None,manifest=None):
        payload=b'PUBLIC synthetic SQL; no content keys or credentials\n'
        manifest=manifest or {'version':1,'purpose':'anynote-consistent-backup','members':[{'path':'database.sql','bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest()}]}
        entries=entries if entries is not None else [('database.sql',payload,'file')]
        raw=io.BytesIO()
        with tarfile.open(fileobj=raw,mode='w',format=tarfile.USTAR_FORMAT) as tar:
            data=json.dumps(manifest).encode();m=tarfile.TarInfo('manifest.json');m.size=len(data);tar.addfile(m,io.BytesIO(data))
            for name,data,kind in entries:
                m=tarfile.TarInfo(name);m.size=len(data)
                if kind=='link':m.type=tarfile.SYMTYPE;m.linkname='/outside'
                tar.addfile(m,io.BytesIO(data) if kind=='file' else None)
        path=self.root/'backup.age';path.unlink(missing_ok=True)
        ops.run([self.age,'-r',self.recipient,'-o',path],input=raw.getvalue());signature=self.root/'signature';signature.write_bytes(ops.sign(path,self.root/'signing'));return path,signature

    def unpack(self,path,signature,identity=None):
        with tempfile.TemporaryDirectory(dir=self.root) as directory:return ops.unpack(path,signature,self.root/'verification',identity or self.root/'identity',self.age,Path(directory))

    def test_complete_independently_signed_archive(self):
        p,s=self.archive();self.assertEqual(self.unpack(p,s)['version'],1)

    def test_wrong_offline_identity(self):
        p,s=self.archive()
        with self.assertRaises(Exception):self.unpack(p,s,self.root/'other')

    def test_corrupt_ciphertext_cannot_reach_decrypt_or_database(self):
        p,s=self.archive();b=bytearray(p.read_bytes());b[-20]^=1;p.write_bytes(b)
        with self.assertRaises(RuntimeError):self.unpack(p,s)

    def test_truncated_but_resigned_age_requires_authenticated_eof(self):
        p,s=self.archive();p.write_bytes(p.read_bytes()[:-30]);s.write_bytes(ops.sign(p,self.root/'signing'))
        with self.assertRaises(Exception):self.unpack(p,s)

    def test_missing_database_rejected(self):
        p,s=self.archive(entries=[])
        with self.assertRaises(ValueError):self.unpack(p,s)

    def test_missing_or_changed_component_rejected(self):
        for entries in [[('database.sql',b'changed','file')], [('blobs/'+'A'*22,b'x','file')]]:
            with self.subTest(entries=entries):
                p,s=self.archive(entries=entries)
                with self.assertRaises(ValueError):self.unpack(p,s)

    def test_unsafe_paths_and_symlinks_rejected(self):
        for path,kind in [('../escaped','file'),('/absolute','file'),('blobs/'+'A'*22,'link')]:
            with self.subTest(path=path):
                p,s=self.archive(entries=[(path,b'','file' if kind=='file' else 'link')])
                with self.assertRaises(ValueError):self.unpack(p,s)

    def test_duplicate_entries_rejected(self):
        payload=b'PUBLIC synthetic SQL; no content keys or credentials\n';p,s=self.archive(entries=[('database.sql',payload,'file')]*2)
        with self.assertRaises(ValueError):self.unpack(p,s)

    def test_no_replace_publication(self):
        original=self.root/'existing';original.write_bytes(b'existing');part=self.root/'partial';part.write_bytes(b'new')
        with self.assertRaises(FileExistsError):ops.publish(part,original)
        self.assertEqual(original.read_bytes(),b'existing');self.assertEqual(part.read_bytes(),b'new')


if __name__=='__main__':unittest.main()
