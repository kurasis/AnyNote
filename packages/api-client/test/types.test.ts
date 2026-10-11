import type {
  P03ApiLiveness,
  P02V1ErrorResponse,
  Operations,
} from "../../contracts/generated/protocol.js";
const live: P03ApiLiveness = { status: "live" };
// @ts-expect-error a future product capability cannot be asserted by the foundation
const implemented: Operations["get_groups"]["implemented"] = true;
// @ts-expect-error unknown fields are invalid DTOs
const extra: P03ApiLiveness = { status: "live", token: "synthetic" };
// @ts-expect-error unknown errors cannot cross the typed boundary
const code: P02V1ErrorResponse["error"]["code"] = "SQL_EXCEPTION";
// @ts-expect-error liveness is a fixed protocol value
const wrong: P03ApiLiveness = { status: "ready" };
void [live, implemented, extra, code, wrong];
