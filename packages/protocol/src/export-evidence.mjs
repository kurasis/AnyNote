// Exact paginated public evidence layout, bounded synthetic collection only.
import { requireCondition as check } from "./strict-json.mjs";
import { decode, encode } from "./protocol-codec.mjs";
import { wire } from "./identity-codec.mjs";
import { stateDecode, stateEncode } from "./state-codec.mjs";
import { decode as fileDecode, encode as fileEncode } from "./codec.mjs";
import { groupCodecForProfile } from "./group-codec.mjs";
const codec = groupCodecForProfile("p02-group-c2"),
  index = (i) => String(i).padStart(8, "0");
export function publicEvidenceEntriesForEvaluation(evidenceBytes) {
  const e = decode("export-evidence", evidenceBytes),
    out = [],
    add = (path, bytes) => out.push({ path, bytes, kind: "identity" });
  for (const a of e.accounts) {
    const prefix = "identity/accounts/" + a.pin.account_id + "/";
    add(
      prefix + "identity.json",
      encode("contact-card", wire({ ...a.pin, identity: a.identity })),
    );
    a.events.forEach((event, i) =>
      add(
        prefix + "roster/" + index(i) + ".json",
        stateEncode("event", wire(event)),
      ),
    );
  }
  for (const g of e.groups) {
    const prefix = "identity/groups/" + g.genesis_pin.group_id + "/";
    add(
      prefix + "genesis.json",
      encode(
        "export-public-group",
        wire({ genesis: g.genesis, genesis_pin: g.genesis_pin }),
      ),
    );
    g.transitions.forEach((t, i) => {
      const record = t.kind === "epoch" ? t.value.record : t.value;
      add(
        prefix + "journal/" + index(i) + ".json",
        encode("export-public-event", wire({ kind: t.kind, record })),
      );
      if (t.kind === "epoch")
        t.value.pages.forEach((page, j) =>
          add(
            prefix +
              "grants/" +
              record.body.operation_id +
              "/" +
              index(j) +
              ".json",
            codec.groupEncode("grant-page", wire(page)),
          ),
        );
    });
    add(
      prefix + "history/checkpoint.json",
      codec.groupEncode("history", wire(g.history)),
    );
    g.history_pages.forEach((page, i) =>
      add(
        prefix + "history/pages/" + index(i) + ".json",
        fileEncode("checkpoint-page", wire(page)),
      ),
    );
  }
  return out;
}
export function assemblePublicEvidenceForEvaluation(entries) {
  const publicEntries = entries.filter((x) => x.path.startsWith("identity/"));
  check(
    publicEntries.reduce((n, x) => n + x.bytes.length, 0) <= 16777216,
    "EVALUATION_RESOURCE_LIMIT",
  );
  const compact = publicEntries.find(
    (e) => e.path === "identity/evidence.json",
  );
  if (compact) {
    check(publicEntries.length === 1, "EXPORT_EVIDENCE_CONFLICT");
    return compact.bytes;
  }
  check(publicEntries.length > 0, "EXPORT_EVIDENCE_MISSING");
  const map = new Map(publicEntries.map((x) => [x.path, x.bytes]));
  check(map.size === publicEntries.length, "DUPLICATE_ARCHIVE_PATH");
  const take = (path) => {
    const b = map.get(path);
    check(b, "EXPORT_EVIDENCE_MISSING");
    map.delete(path);
    return b;
  };
  const indexed = (prefix) => {
    const paths = [...map.keys()].filter((p) => p.startsWith(prefix)).sort();
    for (let i = 0; i < paths.length; i++)
      check(paths[i] === prefix + index(i) + ".json", "INVALID_PAGE_ORDER");
    return paths.map(take);
  };
  const accounts = [];
  for (const path of [...map.keys()]
    .filter((p) =>
      /^identity\/accounts\/[A-Za-z0-9_-]{22}\/identity\.json$/.test(p),
    )
    .sort()) {
    const card = decode("contact-card", take(path)),
      accountId = path.split("/")[2];
    check(card.account_id === accountId, "EXPORT_IDENTITY_MISMATCH");
    const { identity, ...pin } = card;
    const events = indexed("identity/accounts/" + accountId + "/roster/").map(
      (b) => stateDecode("event", b),
    );
    check(events.length > 0, "EXPORT_EVIDENCE_MISSING");
    accounts.push({ identity, pin, events });
  }
  const groups = [];
  for (const path of [...map.keys()]
    .filter((p) =>
      /^identity\/groups\/[A-Za-z0-9_-]{22}\/genesis\.json$/.test(p),
    )
    .sort()) {
    const groupId = path.split("/")[2],
      prefix = "identity/groups/" + groupId + "/",
      base = decode("export-public-group", take(path));
    check(base.genesis_pin.group_id === groupId, "EXPORT_CONTEXT_MISMATCH");
    const transitions = indexed(prefix + "journal/").map((b) => {
      const t = decode("export-public-event", b);
      if (t.kind === "policy") return { kind: "policy", value: t.record };
      const pages = indexed(
        prefix + "grants/" + t.record.body.operation_id + "/",
      ).map((b) => codec.groupDecode("grant-page", b));
      return { kind: "epoch", value: { record: t.record, pages } };
    });
    const history = codec.groupDecode(
        "history",
        take(prefix + "history/checkpoint.json"),
      ),
      history_pages = indexed(prefix + "history/pages/").map((b) =>
        fileDecode("checkpoint-page", b),
      );
    groups.push({ ...base, transitions, history, history_pages });
  }
  check(map.size === 0, "EXPORT_EVIDENCE_UNUSED");
  return encode("export-evidence", wire({ accounts, groups }));
}
