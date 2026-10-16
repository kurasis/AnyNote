#!/usr/bin/env python3
"""Candidate archive tampering and false-release negative tests; no product state."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('candidate', Path(__file__).with_name('p18-candidate.py'))
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)


class Candidate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='anynote-p18-negative-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.payload = self.root / 'payload'; self.payload.write_bytes(b'PUBLIC synthetic bytes\n')
        self.manifest = {'schema': c.SCHEMA, 'role': 'pwa', 'source_commit': 'a'*40,
                         'source_tree': 'b'*40, 'source_tree_dirty': False,
                         'distribution': 'SYNTHETIC_REVIEW_ONLY', 'release_eligibility': c.eligibility()}
        self.path = self.root / 'candidate.tar.gz'

    def build(self):
        return c.write_archive(self.path, copy.deepcopy(self.manifest), {'pwa/auth/notes.js': self.payload})

    def malicious(self, mutate=lambda m: None, entries=None):
        manifest = copy.deepcopy(self.manifest)
        payload = self.payload.read_bytes()
        manifest['files'] = [{'path': 'pwa/auth/notes.js', 'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}]
        mutate(manifest)
        with tarfile.open(self.path, 'w:gz', format=tarfile.USTAR_FORMAT) as tar:
            raw = c.canonical(manifest); info = tarfile.TarInfo('candidate.json'); info.size = len(raw); tar.addfile(info, io.BytesIO(raw))
            for name, raw, kind in entries or [('pwa/auth/notes.js', payload, 'file')]:
                info = tarfile.TarInfo(name); info.size = len(raw)
                if kind == 'symlink':
                    info.type = tarfile.SYMTYPE; info.linkname = '/outside'
                elif kind == 'hardlink':
                    info.type = tarfile.LNKTYPE; info.linkname = 'pwa/auth/notes.js'
                tar.addfile(info, io.BytesIO(raw) if kind == 'file' else None)

    def test_roundtrip_is_deterministic_and_review_only(self):
        first = self.build(); digest = c.sha(self.path)
        other = self.root / 'other.tar.gz'
        c.write_archive(other, copy.deepcopy(self.manifest), {'pwa/auth/notes.js': self.payload})
        self.assertEqual(c.sha(other), digest)
        self.assertEqual(first['release_eligibility']['status'], 'BLOCKED')

    def test_tampered_member(self):
        self.malicious(entries=[('pwa/auth/notes.js', b'forged', 'file')])
        with self.assertRaises(ValueError): c.verify(self.path)

    def test_equal_length_tampering(self):
        self.malicious(entries=[('pwa/auth/notes.js', b'X'*self.payload.stat().st_size, 'file')])
        with self.assertRaises(ValueError): c.verify(self.path)

    def test_missing_member(self):
        self.malicious(entries=[('unlisted', b'', 'file')])
        with self.assertRaises(ValueError): c.verify(self.path)

    def test_unsafe_names_and_duplicate_declarations(self):
        for name in ['../escape', '/absolute', 'C:/escape', 'a\\b', 'a//b', 'a/./b', 'a/../b', 'a\nb', 'candidate.json']:
            with self.subTest(name=name):
                self.malicious(lambda m: m['files'][0].update(path=name))
                with self.assertRaises(ValueError): c.verify(self.path)
        self.malicious(lambda m: m['files'].append(copy.deepcopy(m['files'][0])))
        with self.assertRaises(ValueError): c.verify(self.path)

    def test_link_members(self):
        for kind in ['symlink', 'hardlink']:
            with self.subTest(kind=kind):
                self.malicious(entries=[('pwa/auth/notes.js', b'', kind)])
                with self.assertRaises(ValueError): c.verify(self.path)

    def test_duplicate_actual_member(self):
        self.malicious(entries=[('pwa/auth/notes.js', self.payload.read_bytes(), 'file')]*2)
        with self.assertRaises(ValueError): c.verify(self.path)

    def test_forged_production_clearance(self):
        self.malicious(lambda m: m['release_eligibility'].update(production_release_allowed=True, status='PASS'))
        with self.assertRaises(ValueError): c.verify(self.path)

    def test_missing_external_gate_cannot_be_deleted(self):
        self.malicious(lambda m: m['release_eligibility']['blockers'].pop('qualified_independent_review'))
        with self.assertRaises(ValueError): c.verify(self.path)

    def test_dirty_or_invalid_source(self):
        for key, value in [('source_tree_dirty', True), ('source_commit', 'main'), ('source_tree', 'old')]:
            with self.subTest(key=key):
                self.malicious(lambda m: m.update({key: value}))
                with self.assertRaises(ValueError): c.verify(self.path)

    def test_declared_size_budget(self):
        self.malicious(lambda m: m['files'][0].update(bytes=c.MAX_MEMBER+1))
        with self.assertRaises(ValueError): c.verify(self.path)

    def test_existing_candidate_not_replaced(self):
        self.build(); digest = c.sha(self.path)
        with self.assertRaises(ValueError): self.build()
        self.assertEqual(c.sha(self.path), digest)

    def test_local_symlink_input_is_refused(self):
        link = self.root / 'link'; link.symlink_to(self.payload)
        with self.assertRaises(ValueError):
            c.write_archive(self.path, copy.deepcopy(self.manifest), {'pwa/auth/notes.js': link})

    def test_eligibility_command_is_nonzero(self):
        result = subprocess.run(['python3', str(c.ROOT / 'scripts/p18-candidate.py'), 'eligibility'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIs(json.loads(result.stdout)['production_release_allowed'], False)

    def test_truncated_gzip_trailer_is_not_accepted(self):
        self.build(); self.path.write_bytes(self.path.read_bytes()[:-5])
        with self.assertRaises((ValueError, EOFError, OSError, tarfile.TarError)): c.verify(self.path)

    def test_hidden_content_after_tar_eof_is_not_accepted(self):
        import gzip
        self.build()
        raw = gzip.decompress(self.path.read_bytes())
        self.path.write_bytes(gzip.compress(raw + b'hidden-content'))
        with self.assertRaises(ValueError): c.verify(self.path)

    def test_extension_headers_rejected_before_body_read(self):
        import gzip
        # Valid checksums but no body: rejection must come from header policy,
        # not from attempting to load an attacker-declared multi-gigabyte body.
        for kind in [tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_SPARSE]:
            with self.subTest(kind=kind):
                item = tarfile.TarInfo('extension'); item.type = kind; item.size = c.MAX_MEMBER
                self.path.write_bytes(gzip.compress(item.tobuf(format=tarfile.USTAR_FORMAT)))
                with self.assertRaisesRegex(ValueError, 'No links or extension headers'): c.verify(self.path)

    def test_failed_missing_duplicate_or_wrong_source_cohort_is_refused(self):
        spec = importlib.util.spec_from_file_location('acceptance', c.ROOT / 'scripts/p18-acceptance.py')
        a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)
        names = {r['name'] for r in json.loads((c.ROOT / 'docs/evidence/p14/acceptance.json').read_text())['checks']}
        names |= {'pwa-linux-http-browser', 'pwa-webkit-shell', 'operations-linux-drill', 'operations-capacity', 'adversarial-linux'}
        cohort = {'status': 'PASS', 'mandatory_jobs': 30, 'passed': 30, 'event': 'pull_request',
                  'source_commit': 'a'*40, 'missing': [], 'failed': [],
                  'checks': [{'name': n, 'head_sha': 'a'*40, 'status': 'completed', 'conclusion': 'success', 'run_id': 1} for n in names]}
        downloads = {'source_commit': 'a'*40, 'cohort_status_when_downloaded': 'PASS',
                     'artifacts': [{'name': str(n), 'run_id': 1} for n in range(28)]}
        a.check_cohort(cohort, downloads)
        mutations = [lambda v: v.update(status='PENDING'), lambda v: v.update(passed=29),
                     lambda v: v.update(event='workflow_dispatch'), lambda v: v['checks'].pop(),
                     lambda v: v['checks'].append(copy.deepcopy(v['checks'][0])),
                     lambda v: v['checks'][0].update(head_sha='b'*40),
                     lambda v: v['checks'][0].update(conclusion='failure'),
                     lambda v: v['checks'][0].update(conclusion='skipped')]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                value = copy.deepcopy(cohort); mutate(value)
                with self.assertRaises(ValueError): a.check_cohort(value, downloads)
        for mutate in [lambda v: v.update(source_commit='b'*40), lambda v: v['artifacts'].pop(),
                       lambda v: v['artifacts'][0].update(run_id=9)]:
            with self.subTest(download=mutate):
                value = copy.deepcopy(downloads); mutate(value)
                with self.assertRaises(ValueError): a.check_cohort(cohort, value)


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(Candidate))
    out = c.ROOT / 'artifacts/p17'; out.mkdir(parents=True, exist_ok=True)
    report = {'purpose': 'P18 executed candidate integrity and false-release negatives',
              'status': 'PASS' if result.wasSuccessful() else 'FAIL',
              'source_commit': c.git('rev-parse', 'HEAD').decode().strip(),
              'source_tree_dirty': bool(c.git('status', '--porcelain').strip()),
              'tests_run': result.testsRun, 'failures': len(result.failures),
              'errors': len(result.errors), 'skipped': len(result.skipped),
              'release_eligibility': c.eligibility()}
    (out / 'p18-negative-report.json').write_bytes(c.canonical(report))
    raise SystemExit(0 if result.wasSuccessful() else 1)
