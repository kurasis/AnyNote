#!/usr/bin/env python3
"""Preserve frozen group predicates in the portable custody adapter; read-only default."""
import argparse
from pathlib import Path
root=Path(__file__).resolve().parents[1]
write=argparse.ArgumentParser();write.add_argument('--write',action='store_true');args=write.parse_args()
for name in ['group-state','group-builders']:
 s=(root/'packages/protocol/src'/f'{name}.mjs').read_text()
 s=s.replace('import sodium from "libsodium-wrappers-sumo";', 'import {sodium,Buffer} from "../adapters/primitives.mjs";')
 s=s.replace('"./strict-json.mjs"','"../src/strict-json.mjs"')
 for n in ['identity-codec','codec','group-codec','protocol-codec']:s=s.replace(f'"./{n}.mjs"',f'"../adapters/codecs/{n}.mjs"')
 s=s.replace('"./identity-crypto.mjs"','"../devices/proofs.mjs"').replace('"./roster.mjs"','"../devices/roster.mjs"')
 s=s.replace('import { decryptEvaluationFile } from "../evaluation-file.mjs";', 'const decryptEvaluationFile = () => { throw Error("FILES_PHASE_REQUIRED"); };')
 s=s.replace('import { decryptObjectForEvaluation } from "./object-crypto.mjs";', 'import {openObject as decryptObjectForEvaluation} from "../adapters/core.mjs";')
 if name=='group-state':
  s=s.replace('    const intent = decode("epoch-intent", intentBytes),', '    if(policyBytes && decode("policy", policyBytes).body.action === "genesis"){check(!s.epoch && same(decode("policy", policyBytes),decode("policy",s.policyRecords[0])),"INVALID_GENESIS");policyBytes=null;}\n    const intent = decode("epoch-intent", intentBytes),',1)
  s=s.replace('!s.operations.has(b.operation_id) &&\n        !s.terminal.has(b.operation_id)', '(!s.operations.has(b.operation_id) || (b.reason === "genesis" && !s.epoch && decode("policy",s.policyRecords[0]).body.operation_id === b.operation_id)) &&\n        !s.terminal.has(b.operation_id)',1)
  s='import {stateDigest as stateDigestForCustody} from \"../adapters/codecs/state-codec.mjs\";\n'+s
  s=s.replace('  return Object.freeze({\n    decryptAuthorizedGroupObjectForEvaluation,', (root/'packages/protocol/shared/custody-methods.inc.mjs').read_text()+'\n  return Object.freeze({\n    custodyAccount,custodyHistory,custodyWitnesses,\n    decryptAuthorizedGroupObjectForEvaluation,',1)
 s='// Generated portable frozen group predicates. Durable custody and independent anchors are separate.\n'+s
 path=root/'packages/protocol/shared'/f'{name}.mjs'
 if args.write:path.write_text(s)
 else:assert path.read_text()==s,'P10 frozen predicate drift: '+name
print('PASS: P10 portable frozen group predicates')
