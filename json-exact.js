/**
 * Bounded JSON structural validator preventing prototype pollution, duplicate
 * property shadowing, excessive nesting depth, or oversized numeric exponents.
 */

export const JSON_LIMITS = {
  bytes: 5 * 1024 * 1024,
  depth: 100,
  nodes: 200000,
  numberDigits: 1000,
  exponent: 10000,
};

export class JsonIssue extends Error {
  constructor(code, path = '', offset = 0) {
    super(code);
    this.code = code;
    this.path = path;
    this.offset = offset;
  }
}

export function escapePointer(value) {
  return value.replace(/~/g, '~0').replace(/\//g, '~1');
}

export function exactNumber(raw, limits = JSON_LIMITS) {
  const match = /^(-?)(0|[1-9]\d*)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(raw);
  if (!match) throw new JsonIssue('syntax');
  const fraction = match[3] ?? '';
  const exponent = Number(match[4] ?? '0');
  if (
    match[2].length + fraction.length > limits.numberDigits ||
    Math.abs(exponent) > limits.exponent
  ) {
    throw new JsonIssue('numberLimit');
  }
  let digits = (match[2] + fraction).replace(/^0+/, '');
  if (!digits) return '0';
  let power = exponent - fraction.length;
  while (digits.endsWith('0')) {
    digits = digits.slice(0, -1);
    power += 1;
  }
  return `${match[1]}${digits}e${power}`;
}

class JsonExactParser {
  constructor(text, limits) {
    this.text = text;
    this.limits = limits;
    this.at = 0;
    this.count = 0;
  }

  fail(code, path) {
    throw new JsonIssue(code, path, this.at);
  }

  space() {
    while (/[\x20\t\r\n]/.test(this.text[this.at] ?? '') && this.at < this.text.length) {
      this.at += 1;
    }
  }

  string(path) {
    const start = this.at;
    this.at += 1;
    while (this.at < this.text.length) {
      const c = this.text[this.at];
      this.at += 1;
      if (c === '"') {
        try {
          return JSON.parse(this.text.slice(start, this.at));
        } catch {
          return this.fail('syntax', path);
        }
      }
      if (c === '\\') this.at += 1;
    }
    return this.fail('syntax', path);
  }

  parseCompoundChildren(object, depth, path) {
    const children = new Map();
    do {
      this.space();
      let key = String(children.size);
      if (object) {
        if (this.text[this.at] !== '"') this.fail('syntax', path);
        key = this.string(path);
        this.space();
        if (children.has(key)) this.fail('duplicateProperty', `${path}/${escapePointer(key)}`);
        if (this.text[this.at] !== ':') this.fail('syntax', path);
        this.at += 1;
      }
      children.set(key, this.node(depth + 1, `${path}/${escapePointer(key)}`));
      this.space();
      if (this.text[this.at] !== ',') break;
      this.at += 1;
    } while (true);
    return children;
  }

  parseCompound(c, depth, path) {
    const start = this.at;
    const object = c === '{';
    const endChar = object ? '}' : ']';
    this.at += 1;
    this.space();
    const children =
      this.text[this.at] !== endChar
        ? this.parseCompoundChildren(object, depth, path)
        : new Map();
    if (this.text[this.at] !== endChar) this.fail('syntax', path);
    this.at += 1;
    return { kind: object ? 'object' : 'array', start, end: this.at, children };
  }

  parseLiteral(start) {
    for (const [literal, kind, value] of [
      ['true', 'boolean', true],
      ['false', 'boolean', false],
      ['null', 'null', undefined],
    ]) {
      if (this.text.startsWith(literal, this.at)) {
        this.at += literal.length;
        return { kind, start, end: this.at, value };
      }
    }
    return null;
  }

  parseNumber(start, path) {
    const token = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(this.text.slice(this.at));
    if (!token) return this.fail('syntax', path);
    this.at += token[0].length;
    try {
      return { kind: 'number', start, end: this.at, value: exactNumber(token[0], this.limits) };
    } catch (error) {
      return this.fail(error.code, path);
    }
  }

  node(depth, path) {
    if (depth > this.limits.depth) this.fail('depth', path);
    this.count += 1;
    if (this.count > this.limits.nodes) this.fail('nodes', path);
    this.space();
    const start = this.at;
    const c = this.text[this.at];
    if (c === '{' || c === '[') return this.parseCompound(c, depth, path);
    if (c === '"') return { kind: 'string', start, value: this.string(path), end: this.at };
    const literalNode = this.parseLiteral(start);
    if (literalNode) return literalNode;
    return this.parseNumber(start, path);
  }
}

export function parseExactJson(text, limits = JSON_LIMITS) {
  if (new TextEncoder().encode(text).byteLength > limits.bytes) throw new JsonIssue('tooLarge');
  const parser = new JsonExactParser(text, limits);
  const result = parser.node(0, '');
  parser.space();
  if (parser.at !== text.length) parser.fail('syntax', '');
  return result;
}
