// Termination discards an in-flight worker. Vault-generation fencing belongs to P07.
export class CryptoWorker {
  #worker;
  #ready;
  #pending = null;
  #next = 0;
  #closed = false;
  #rejectReady;
  constructor(url) {
    this.#worker = new Worker(url, { type: "module" });
    this.#ready = new Promise((resolve, reject) => {
      this.#rejectReady = reject;
      this.#worker.onmessage = ({ data: r }) => {
        if (r?.version !== 1) return;
        if (r.status === "READY") {
          resolve();
          return;
        }
        const p = this.#pending;
        if (!p || r.id !== p.id) return;
        this.#pending = null;
        r.error
          ? p.reject(Object.assign(new Error(r.error), { code: r.error }))
          : p.resolve(r.result);
      };
      this.#worker.onerror = () => {
        reject(new Error("WORKER_FAILED"));
        this.close("WORKER_FAILED");
      };
    });
    this.#ready.catch(() => {});
  }
  async call(op, args, transfer = []) {
    if (!Array.isArray(args) || args.length > 6)
      throw new Error("INVALID_WORKER_REQUEST");
    let bytes = 0;
    for (const a of args) {
      if (a instanceof Uint8Array) bytes += a.byteLength;
      else if (typeof a === "string") {
        if (a.length > 8388608) throw new Error("RESOURCE_LIMIT");
        bytes += new TextEncoder().encode(a).length;
      } else throw new Error("INVALID_WORKER_REQUEST");
    }
    if (bytes > 8388608) throw new Error("RESOURCE_LIMIT");
    await this.#ready;
    if (this.#closed) throw new Error("WORKER_CLOSED");
    if (this.#pending) throw new Error("WORKER_BUSY");
    return new Promise((resolve, reject) => {
      const id = ++this.#next;
      this.#pending = { id, resolve, reject };
      try {
        this.#worker.postMessage({ version: 1, id, op, args }, transfer);
      } catch {
        this.#pending = null;
        reject(new Error("INVALID_WORKER_REQUEST"));
      }
    });
  }
  close(code = "WORKER_CLOSED") {
    if (!this.#closed) {
      this.#closed = true;
      this.#worker.terminate();
      this.#rejectReady(new Error(code));
      this.#pending?.reject(new Error(code));
      this.#pending = null;
    }
  }
}
