#!/usr/bin/env python3
"""Assemble an offline P18 review set from the complete ordinary CI cohort.

Inputs are public receipts obtained from the GitHub API by the operator, not a new
trust anchor. All ZIP digests, actual Git blobs and inherited runtime assertions
are rechecked. No upload, deployment, signing or production clearance occurs.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('candidate', ROOT / 'scripts/p18-candidate.py')
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)


def check_cohort(cohort, downloads):
    expected = {r['name'] for r in json.loads((ROOT / 'docs/evidence/p14/acceptance.json').read_text())['checks']}
    expected |= {'pwa-linux-http-browser', 'pwa-webkit-shell', 'operations-linux-drill', 'operations-capacity', 'adversarial-linux'}
    c.require(len(expected) == 30 and cohort['status'] == 'PASS' and cohort['mandatory_jobs'] == cohort['passed'] == 30,
              'All thirty ordinary jobs must pass')
    c.require(cohort['event'] in ('pull_request', 'push') and not cohort['missing'] and not cohort['failed'], 'Incomplete ordinary cohort')
    rows = cohort['checks']
    c.require(len(rows) == 30 and {r['name'] for r in rows} == expected, 'Missing/duplicate required check')
    for row in rows:
        c.require(row['head_sha'] == cohort['source_commit'] and row['status'] == 'completed' and row['conclusion'] == 'success', 'Failed/stale check')
    c.require(downloads['source_commit'] == cohort['source_commit'] and downloads['cohort_status_when_downloaded'] == 'PASS', 'Wrong downloaded cohort')
    run_ids = {r['run_id'] for r in rows}
    c.require(len(downloads['artifacts']) == 28 and len({r['name'] for r in downloads['artifacts']}) == 28, 'Incomplete artifact set')
    c.require(all(r['run_id'] in run_ids for r in downloads['artifacts']), 'Artifact outside observed ordinary cohort')


def acceptance(cohort_path, folder, output):
    c.require(not output.exists(), 'New output directory required; previous evidence is preserved')
    cohort = json.loads(cohort_path.read_text()); downloads = json.loads((folder / 'download-receipt.json').read_text())
    check_cohort(cohort, downloads)
    for script, args in [('audit-cohort.py', [str(folder)]),
                         ('verify-p17.py', [str(folder), str(folder / 'p18-inherited-verification.json')])]:
        subprocess.run(['python3', str(ROOT / 'scripts/release' / script), *args], cwd=ROOT, check=True, capture_output=True)
    audit = json.loads((folder / 'audit-receipt.json').read_text())
    head = audit['candidate_head']; tree = audit['candidate_tree']

    def raw(artifact, suffix):
        rows = [r for r in audit['reports'] if r['artifact_name'] == artifact and r['member'].endswith(suffix)]
        c.require(len(rows) == 1, 'Missing/ambiguous report: ' + artifact + '/' + suffix)
        row = rows[0]
        with zipfile.ZipFile(folder / (str(row['artifact_id']) + '.zip')) as z:
            data = z.read(row['member'])
        c.require(hashlib.sha256(data).hexdigest() == row['sha256'], 'Raw report changed')
        return json.loads(data), row

    negative, _ = raw('p17-security-report', 'p18-negative-report.json')
    c.require(negative['status'] == 'PASS' and negative['source_commit'] == head and negative['source_tree_dirty'] is False
              and negative['tests_run'] >= 19 and negative['failures'] == negative['errors'] == negative['skipped'] == 0,
              'Candidate integrity negative suite did not pass')
    operations, _ = raw('p16-operations-report', 'operations-report.json')
    journey = operations['p18_journey']
    c.require(journey['status'] == 'PASS' and journey['completed_stages'] == ['install', 'enroll', 'share', 'upload', 'revoke', 'recover', 'restore'], 'Missing linked final journey')
    c.require([e['stage'] for e in journey['events']] == ['enroll', 'share', 'upload', 'revoke'], 'Incomplete same-owner journey')
    c.require(journey['owner_account_id'] == journey['events'][1]['evidence']['owner_account_id'], 'Journey owner changed')
    c.require(journey['private_file_bytes'] == 1000000000 and journey['private_file_source_sha256'] == journey['private_file_recovered_sha256'] == journey['private_file_fresh_download_sha256'], 'Final recovered/fresh file mismatch')
    c.require(journey['old_credentials_quarantined'] is True and journey['shared_root_kit_recovery'] is False and journey['root_reset_generation'] == '1', 'Recovery authority expanded')
    revoked = journey['events'][-1]['evidence']
    c.require(all(revoked[k] is True for k in ['manifest_denied', 'group_denied', 'removed_recipient_excluded', 'fresh_epoch_publication']), 'Revocation not established')
    upload = journey['events'][2]['evidence']
    c.require(upload['plaintext_sha256'] == upload['independent_recipient_hash'] and upload['plaintext_bytes'] > 0, 'Shared file mismatch')

    with tempfile.TemporaryDirectory(prefix='anynote-p18-final-') as tmp:
        stage = Path(tmp); packages = []
        for role, artifact in [('windows', 'p14-windows-development-installer'), ('pwa', 'p15-linux-pwa-report'), ('api', 'p16-operations-report')]:
            receipt, row = raw(artifact, role + '-candidate-report.json')
            c.require(receipt['status'] == 'PASS' and receipt['source_commit'] == head and receipt['source_tree'] == tree and receipt['source_tree_dirty'] is False, 'Stale candidate receipt')
            ref = receipt['candidate']; c.safe_name(ref['path']); c.require('/' not in ref['path'], 'Flat candidate filename required')
            dest = stage / ref['path']
            with zipfile.ZipFile(folder / (str(row['artifact_id']) + '.zip')) as z:
                names = [n for n in z.namelist() if n.endswith('/' + ref['path']) or n == ref['path']]
                c.require(len(names) == 1, 'Missing/duplicate packaged candidate')
                info = z.getinfo(names[0]); c.require(info.file_size == ref['bytes'] <= c.MAX_TOTAL, 'Candidate ZIP size mismatch')
                with z.open(info) as source, dest.open('xb') as target:
                    shutil.copyfileobj(source, target, 1048576)
            c.require(c.sha(dest) == ref['sha256'], 'Packaged candidate digest mismatch')
            manifest = c.verify(dest)
            c.require(manifest['source_commit'] == head and manifest['source_tree'] == tree and manifest['role'] == role, 'Mixed-source candidate')
            c.require(hashlib.sha256(c.canonical(manifest)).hexdigest() == receipt['manifest_sha256'], 'Manifest changed')
            # The full source archive must be byte-for-byte git archive of this head.
            original = stage / 'source.tar'
            with original.open('wb') as target:
                subprocess.run(['git', 'archive', '--format=tar', head], cwd=ROOT, stdout=target, check=True)
            declared = {r['path']: r for r in manifest['files']}
            c.require(declared['source/AnyNote-source.tar']['sha256'] == c.sha(original), 'Corresponding source differs from Git')
            if role == 'windows':
                windows, _ = raw(artifact, 'p14/source-report.json')
                matches = [v for k, v in declared.items() if k.startswith('windows/') and k.endswith('.exe')]
                c.require(len(matches) == 1 and matches[0]['sha256'] == windows['installer']['sha256'], 'Installer differs from executed receipt')
            elif role == 'pwa':
                pwa, _ = raw(artifact, 'p15/source-report.json')
                c.require({r['path']: r['sha256'] for r in pwa['static_inputs']} ==
                          {k.removeprefix('pwa/auth/'): v['sha256'] for k, v in declared.items() if k.startswith('pwa/auth/')}, 'PWA differs from executed static bytes')
            packages.append({**ref, 'role': role, 'artifact_id': row['artifact_id'], 'artifact_name': artifact,
                             'artifact_url': next(a['details_url'] for a in cohort['checks'] if a['name'] == {'windows': 'host-windows-build', 'pwa': 'pwa-linux-http-browser', 'api': 'operations-linux-drill'}[role]),
                             'retention_days': 14, 'manifest_sha256': receipt['manifest_sha256']})
            (stage / (role + '-manifest.json')).write_bytes(c.canonical(manifest))
        original.unlink()
        matrix = matrix_for(cohort, audit)
        result = {'purpose': 'P18 exact-artifact final synthetic acceptance and handoff; no production publication',
                  'status': 'PASS', 'scope': 'Software review candidate only', 'source_commit': head, 'source_tree': tree,
                  'ordinary_event': cohort['event'], 'mandatory_jobs': 30, 'packages': packages,
                  'raw_report_members': len(audit['reports']), 'git_input_rows_verified': audit['git_input_rows_verified'],
                  'journey': journey, 'release_eligibility': c.eligibility(),
                  'evidence_trust': 'Operator-observed GitHub API receipts plus actual Git blobs; checksums alone are not independent publisher authentication',
                  'retention': 'Actions attachments expire after 14 days. Keep this entire offline set with its original ZIP receipts before expiry. No GitHub Release or production deploy was created.'}
        (stage / 'acceptance.json').write_bytes(c.canonical(result))
        (stage / 'matrix.json').write_bytes(c.canonical(matrix))
        (stage / 'cohort.json').write_bytes(cohort_path.read_bytes())
        (stage / 'raw-report-audit.json').write_bytes((folder / 'audit-receipt.json').read_bytes())
        for name in ['p18-inherited-verification.json', 'p18-inherited-verification-p15.json', 'p18-inherited-verification-p16.json']:
            (stage / name).write_bytes((folder / name).read_bytes())
        for name in ['P18_RELEASE.md', 'USER_GUIDE.md', 'OPERATOR_HANDOFF.md']:
            (stage / name).write_bytes(c.git('show', head + ':docs/' + name))
        lines = [c.sha(p) + '  ' + p.name for p in sorted(stage.iterdir()) if p.is_file()]
        (stage / 'SHA256SUMS').write_text('\n'.join(lines) + '\n', encoding='utf-8')
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(stage, output)
    print(json.dumps({'status': 'PASS', 'source_commit': head, 'packages': len(packages), 'matrix_cases': len(matrix['cases']), 'production_release_allowed': False}))


def matrix_for(cohort, audit):
    # Frozen criterion text is preserved verbatim. Passing a related whole suite
    # is not relabelled as case-level or physical acceptance of every outcome.
    text = c.git('show', cohort['source_commit'] + ':docs/spec/13_TESTING_AND_ACCEPTANCE.md').decode()
    definitions = {}
    for match in re.finditer(r'^\| ([FCSU]\d\d) \| (.*?) \| (.*?) \|$', text, re.M):
        definitions[match[1]] = match[2] + ': ' + match[3]
    for match in re.finditer(r'^([XO]\d\d): (.+)$', text, re.M):
        definitions[match[1]] = match[2]
    trace = json.loads(c.git('show', cohort['source_commit'] + ':docs/security/p17-traceability.json'))
    for row in trace['regressions']:
        definitions[row['id']] = row['scenario'] + ': ' + row['required_outcome']
    c.require(len(definitions) == 95, 'Incomplete frozen F/C/S/U/X/O/R matrix')
    family = {'F': ['p06-linux-authentication-report', 'p08-linux-devices-report', 'p10-linux-shared-report'],
              'C': ['p05-linux-crypto-report', 'p08-linux-devices-report', 'p10-linux-shared-report', 'p17-security-report'],
              'S': ['p11-linux-sync-report', 'p14-windows-development-installer', 'p15-linux-pwa-report', 'p16-operations-report'],
              'U': ['p12-linux-files-report', 'p13-linux-content-report', 'p14-windows-development-installer', 'p16-capacity-report'],
              'X': ['p14-windows-development-installer', 'p15-linux-pwa-report', 'p17-security-report'],
              'O': ['p16-operations-report', 'p16-capacity-report'], 'R': ['p17-security-report']}
    cases = []
    observed = {
        'C08': 'Five pre-allocation KDF negatives and malformed bounded envelopes were asserted by the inherited P17 verifier.',
        'C13': 'The same-owner root-signed reset advances generation, revokes the old device/session, and the restored old credential remains quarantined.',
        'S11': 'The inherited exact P15 verifier asserts waiting-worker activation, original accepted receipt and unchanged retained encrypted outbox/newer draft.',
        'S12': 'The inherited P16 verifier asserts changed restore generation, preserved original cursor/draft/outbox and blocked old credentials.',
        'O01': 'The operations driver refuses reused datadirs and creates a clean hardened installation; actual runtime DML/no-code-write checks passed.',
        'O02': 'Actual concurrent acknowledged writes, signed age backup, clean-host restore, independent offline full1GB recovery and fresh-service download hashes passed.',
        'O03': 'Actual8MiB tmpfs ENOSPC, directory-fsync denial, DB outage and supervised queue restart passed without changing production reserve.',
        'O04': 'The actual cleanup report asserts expired invitations/enrollments/uploads removed, committed references preserved and second maintenance idempotent.',
        'O05': 'The actual incident report checks modified static inventory rejection/isolation and missing recovery secret refusal before output.',
    }
    external = {'U08': ('BLOCKED', 'Actual 100 GB inventory NOT_RUN; bounded quota races are separate.'),
                'U10': ('FAIL', 'Correct 1 GB Windows bytes are verified, but prior measured native/helper growth 339361792 bytes exceeds 128 MiB; no budget closure.'),
                'U11': ('NOT_RUN', 'Physical iPhone 1 GB save and memory evidence unavailable.'),
                'U12': ('NOT_RUN', 'Physical iPhone background/force-close/low-space evidence unavailable.'),
                'X06': ('NOT_RUN', 'Owned synthetic canary inspection passed; real APM/crash/OS remnants are not covered.'),
                'X10': ('NOT_RUN', 'Hosted Windows DPAPI is not the owner physical Hello/TPM trial.'),
                'O06': ('BLOCKED', '10 accounts,50 devices,100000 retained revisions measured; actual 100 GB NOT_RUN.')}
    for ident, definition in sorted(definitions.items()):
        status, limitation = external.get(ident, ('PASS', observed[ident]) if ident in observed else
                                          ('NOT_RUN', 'Related exact-source suites ran successfully. This assembler does not infer complete per-criterion acceptance from whole-suite counts; case-level acceptance remains unrecorded.'))
        evidence = [r for r in audit['reports'] if r['artifact_name'] in family[ident[0]]]
        c.require(evidence, 'Missing related execution evidence for ' + ident)
        cases.append({'id': ident, 'requirement': definition, 'status': status, 'scope': 'Synthetic software only; qualified/physical/production acceptance separate', 'limitation': limitation,
                      'related_executed_software_evidence': [{'artifact_id': r['artifact_id'], 'member': r['member'], 'sha256': r['sha256'], 'status_as_reported': r['status_as_reported']} for r in evidence],
                      **({'authority_and_test_bindings': next(r for r in trace['regressions'] if r['id'] == ident)} if ident.startswith('R') else {})})
    gates = [{'id': 'G' + str(n), 'status': 'BLOCKED' if n in (0, 1, 2, 3, 4) else 'PASS',
              'scope': 'Synthetic software handoff only' if n in (5, 6) else 'Full advertised production outcome is not accepted',
              'production_pass': False} for n in range(7)]
    return {'scope': 'Full frozen criteria alongside related actual software execution; NOT_RUN is not a software-suite failure and suite PASS is not criterion completion',
            'source_commit': cohort['source_commit'], 'cases': cases, 'gates': gates,
            'software_cohort_status': 'PASS', 'production_release_allowed': False,
            'environment_and_date': [{'job': r['name'], 'url': r['details_url'], 'started_at': r['started_at'], 'completed_at': r['completed_at']} for r in cohort['checks']]}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cohort', type=Path, required=True); parser.add_argument('--downloads', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); acceptance(args.cohort, args.downloads, args.output)
