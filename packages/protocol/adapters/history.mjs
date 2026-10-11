import { sodium, un64 } from "./primitives.mjs";
import { wire, same } from "./codecs/identity-codec.mjs";
import { groupCodecForProfile } from "./codecs/group-codec.mjs";
import {
  checkCheckpoint,
  decode as fileDecode,
  signingInput as fileSigningInput,
  envelopeDigest,
} from "./codecs/codec.mjs";
import { decode, signingInput, digest } from "./codecs/protocol-codec.mjs";
import { requireCondition as check } from "../src/strict-json.mjs";
const group = groupCodecForProfile("p02-group-c2");
export class HistoryAnchor {
  #descriptor;
  #records;
  constructor(historyBytes, pageInputs, independentDigest, signerKey) {
    check(
      Array.isArray(pageInputs) &&
        pageInputs.length <= 200 &&
        pageInputs.reduce((n, b) => n + b.length, 0) <= 33554432,
      "RESOURCE_LIMIT",
    );
    const h = group.groupDecode("history", historyBytes),
      d = h.body.descriptor;
    check(
      group.groupDigest("history", historyBytes) === independentDigest,
      "HISTORY_PIN_MISMATCH",
    );
    check(
      sodium.crypto_sign_verify_detached(
        un64(h.signature),
        group.groupSigningInput("history-body", wire(h.body)),
        signerKey,
      ),
      "INVALID_SIGNATURE",
    );
    check(
      h.body.service_id === d.service_id && h.body.group_id === d.group_id,
      "CONTEXT_MISMATCH",
    );
    check(
      sodium.crypto_sign_verify_detached(
        un64(h.body.descriptor_signature),
        fileSigningInput("checkpoint", wire(d)),
        signerKey,
      ),
      "INVALID_SIGNATURE",
    );
    checkCheckpoint(wire(d), pageInputs, d.predecessor_checkpoint_digest);
    this.#descriptor = d;
    this.#records = new Map(
      pageInputs
        .flatMap((b) => fileDecode("checkpoint-page", b).records)
        .map((r) => [r.revision_id, r]),
    );
  }
  checkObject(envelopeBytes, authorKey) {
    const e = decode("envelope", envelopeBytes),
      c = e.header.context,
      d = this.#descriptor,
      r = this.#records.get(c.revision_id);
    check(
      sodium.crypto_sign_verify_detached(
        un64(e.signature),
        signingInput("header", wire(e.header)),
        authorKey,
      ),
      "INVALID_SIGNATURE",
    );
    check(
      c.service_id === d.service_id && c.group_id === d.group_id,
      "UNANCHORED_HISTORY",
    );
    check(
      r &&
        r.object_kind === c.object_kind &&
        r.object_id === c.object_id &&
        same(r.parents, c.parents) &&
        r.envelope_digest === digest("envelope", envelopeBytes),
      "UNANCHORED_HISTORY",
    );
    return true;
  }
  checkFile(envelopeBytes, authorKey) {
    const e = fileDecode("envelope", envelopeBytes),
      c = e.header.context,
      d = this.#descriptor,
      r = this.#records.get(c.file_version_id);
    check(
      sodium.crypto_sign_verify_detached(
        un64(e.signature),
        fileSigningInput("header", wire(e.header)),
        authorKey,
      ),
      "INVALID_SIGNATURE",
    );
    check(
      c.service_id === d.service_id && c.group_id === d.group_id,
      "UNANCHORED_HISTORY",
    );
    check(
      r &&
        r.object_kind === "file-manifest" &&
        r.object_id === c.file_id &&
        same(r.parents, c.parents) &&
        r.envelope_digest === envelopeDigest(envelopeBytes),
      "UNANCHORED_HISTORY",
    );
    return true;
  }
}
