import { visit } from 'jsonc-parser';

export class ContractError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

export function requireCondition(condition, code) {
  if (!condition) throw new ContractError(code);
}

// Raw bytes are mandatory: JSON.parse alone loses duplicate properties and
// Buffer.toString silently replaces malformed UTF-8. Never log rejected input.
export function strictJson(bytes, maximumBytes = 1_048_576) {
  requireCondition(bytes instanceof Uint8Array, 'RAW_BYTES_REQUIRED');
  requireCondition(bytes.byteLength <= maximumBytes, 'RESOURCE_LIMIT');
  let source;
  try {
    source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new ContractError('INVALID_UTF8');
  }
  requireCondition(!source.startsWith('\ufeff'), 'INVALID_JSON');
  const frames = [];
  const validString = value => requireCondition(value.isWellFormed(), 'INVALID_UNICODE');
  const begin = kind => {
    requireCondition(frames.length < 32, 'RESOURCE_LIMIT');
    frames.push(kind === 'object' ? new Set() : null);
  };
  visit(source, {
    onObjectBegin: () => begin('object'),
    onArrayBegin: () => begin('array'),
    onObjectEnd: () => frames.pop(),
    onArrayEnd: () => frames.pop(),
    onObjectProperty: name => {
      validString(name);
      const keys = frames.at(-1);
      requireCondition(!keys.has(name), 'DUPLICATE_PROPERTY');
      keys.add(name);
    },
    onLiteralValue: value => {
      if (typeof value === 'string') validString(value);
      if (typeof value === 'number') requireCondition(Number.isFinite(value), 'NONFINITE_NUMBER');
    },
    onError: () => { throw new ContractError('INVALID_JSON'); },
  }, { disallowComments: true, allowTrailingComma: false, allowEmptyContent: false });
  try {
    return JSON.parse(source);
  } catch {
    throw new ContractError('INVALID_JSON');
  }
}
