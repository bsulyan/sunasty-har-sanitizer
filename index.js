/* @ts-self-types="./index.d.ts" */
/**
 * sunasty-har-sanitizer
 *
 * Zero-dependency HAR 1.2 whitelist sanitizer, forensic location inspector,
 * waterfall timing analyzer, and cURL generator.
 * Extracted from https://sunasty.com/har-sanitizer/
 */

import { parseExactJson, JSON_LIMITS } from './json-exact.js';

export const HAR_MAX_BYTES = 30 * 1024 * 1024;
export const HAR_MAX_ENTRIES = 20000;
export const HAR_LIMITS = { bytes: HAR_MAX_BYTES, entries: HAR_MAX_ENTRIES, decodedBytes: 1024 * 1024 };

export class HarIssue extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function list(value) {
  return Array.isArray(value) ? value : [];
}

function string(value) {
  return typeof value === 'string' ? value : '';
}

function finite(value, fallback = -1) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1e15 ? value : fallback;
}

function url(value) {
  try {
    const result = new URL(string(value));
    return ['http:', 'https:'].includes(result.protocol) ? result : null;
  } catch {
    return null;
  }
}

function mime(value) {
  const raw = string(value).split(';')[0].trim().toLowerCase();
  return /^(?:application\/(?:json|xml|octet-stream|x-www-form-urlencoded)|text\/(?:plain|html|css|csv|xml|javascript)|image\/(?:png|jpeg|gif|webp|svg\+xml)|font\/(?:woff|woff2)|audio\/(?:mpeg|ogg)|video\/(?:mp4|webm))$/.test(raw)
    ? raw
    : 'application/octet-stream';
}

function bodyAllowed(value, response) {
  const body = record(value);
  return (
    typeof body.text === 'string' &&
    new TextEncoder().encode(body.text).byteLength <= HAR_LIMITS.decodedBytes &&
    !body.encoding &&
    (response || list(body.params).length === 0) &&
    [
      'application/json',
      'application/xml',
      'application/x-www-form-urlencoded',
      'text/plain',
      'text/html',
      'text/css',
      'text/csv',
      'text/xml',
      'text/javascript',
    ].includes(mime(body.mimeType))
  );
}

function isLeapYear(year) {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function isValidDateParts(year, month, day) {
  if (month < 1 || month > 12) return false;
  const days = [31, isLeapYear(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day >= 1 && day <= days[month - 1];
}

function isValidTimeParts(h, m, s) {
  return h <= 23 && m <= 59 && s <= 59;
}

function timestamp(value) {
  const raw = string(value);
  const parts = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)$/.exec(raw);
  if (!parts) return null;
  const year = Number(parts[1]);
  const month = Number(parts[2]);
  const day = Number(parts[3]);
  if (!isValidDateParts(year, month, day)) return null;
  if (!isValidTimeParts(Number(parts[4]), Number(parts[5]), Number(parts[6]))) return null;
  const normalized = /([+-]\d\d)(\d\d)$/.test(raw) ? raw.replace(/([+-]\d\d)(\d\d)$/, '$1:$2') : raw;
  const parsed = Date.parse(normalized);
  return Number.isFinite(parsed) ? parsed : null;
}

export function parseHarDocument(text) {
  parseExactJson(text, { ...JSON_LIMITS, bytes: HAR_LIMITS.bytes, depth: 60, nodes: 1000000 });
  const document = record(JSON.parse(text));
  const log = record(document.log);
  if (log.version !== '1.2' || !Array.isArray(log.entries)) throw new HarIssue('invalidHar');
  if (log.entries.length > HAR_LIMITS.entries) throw new HarIssue('tooManyEntries');
  for (const value of log.entries) {
    const entry = record(value);
    if (!Object.keys(record(entry.request)).length || !Object.keys(record(entry.response)).length) {
      throw new HarIssue('invalidHar');
    }
  }
  return document;
}

function inspectEntryLocations(entry, base, location, unknown) {
  const request = record(entry.request);
  const response = record(entry.response);
  location(`${base}/request/url`, 'url', request.url);
  location(`${base}/response/redirectURL`, 'url', response.redirectURL);
  location(`${base}/response/statusText`, 'metadata', response.statusText);
  location(`${base}/response/content/mimeType`, 'metadata', record(response.content).mimeType);
  for (const [name, object] of [['request', request], ['response', response]]) {
    for (const field of ['headers', 'cookies']) {
      list(object[field]).forEach((item, n) =>
        location(`${base}/${name}/${field}/${n}`, field === 'headers' ? 'header' : 'cookie', item),
      );
    }
    location(`${base}/${name}/comment`, 'metadata', object.comment);
    location(`${base}/${name}/httpVersion`, 'metadata', object.httpVersion);
    unknown(
      object,
      name === 'request'
        ? ['method', 'url', 'httpVersion', 'cookies', 'headers', 'queryString', 'postData', 'headersSize', 'bodySize', 'comment']
        : ['status', 'statusText', 'httpVersion', 'cookies', 'headers', 'content', 'redirectURL', 'headersSize', 'bodySize', 'comment'],
      `${base}/${name}`,
    );
  }
  location(`${base}/request/queryString`, 'url', request.queryString);
  location(`${base}/request/postData`, 'body', request.postData);
  location(`${base}/response/content/text`, 'body', record(response.content).text);
  unknown(record(response.content), ['size', 'compression', 'mimeType', 'text', 'encoding', 'comment'], `${base}/response/content`);
  location(`${base}/response/content/comment`, 'metadata', record(response.content).comment);
  for (const field of ['startedDateTime', 'serverIPAddress', 'connection', 'comment', 'pageref', 'cache']) {
    location(`${base}/${field}`, 'metadata', entry[field]);
  }
  unknown(entry, ['startedDateTime', 'time', 'request', 'response', 'cache', 'timings', 'serverIPAddress', 'connection', 'comment', 'pageref'], base);
  unknown(record(entry.timings), ['blocked', 'dns', 'connect', 'send', 'wait', 'receive', 'ssl'], `${base}/timings`);
}

function inspection(log, document) {
  const domains = new Map();
  const entries = [];
  const locations = [];
  let totalLocations = 0;
  const location = (path, category, value) => {
    if (value === undefined) return;
    totalLocations += 1;
    if (locations.length < 1000) {
      locations.push({ path, category, preview: JSON.stringify(value).slice(0, 500), retained: true });
    }
  };
  const unknown = (value, allowed, path) => {
    const extra = Object.keys(value).filter((key) => !allowed.includes(key));
    if (extra.length) location(`${path}/[unknown]`, 'unknown', extra.map((key) => value[key]));
  };
  location('/log/pages', 'metadata', log.pages);
  location('/log/comment', 'metadata', log.comment);
  location('/log/creator', 'metadata', log.creator);
  location('/log/browser', 'metadata', log.browser);
  unknown(document, ['log'], '');
  unknown(log, ['version', 'entries', 'pages', 'comment', 'creator', 'browser'], '/log');
  list(log.entries).forEach((value, index) => {
    const entry = record(value);
    const request = record(entry.request);
    const response = record(entry.response);
    const base = `/log/entries/${index}`;
    const domain = url(request.url)?.host ?? '';
    domains.set(domain, (domains.get(domain) ?? 0) + 1);
    entries.push({
      index,
      domain,
      method: string(request.method).slice(0, 20),
      requestBodyAllowed: bodyAllowed(request.postData, false),
      responseBodyAllowed: bodyAllowed(response.content, true),
    });
    inspectEntryLocations(entry, base, location, unknown);
  });
  return {
    domains: [...domains].map(([domain, count]) => ({ domain, entries: count })),
    entries,
    locations,
    totalLocations,
  };
}

export function inspectParsedHar(document) {
  return inspection(record(document.log), document);
}

export function inspectHar(text) {
  return inspectParsedHar(parseHarDocument(text));
}

function validatePolicy(policy, before) {
  const uniqueDomains = new Set(policy.domains).size === policy.domains.length;
  const knownDomains = policy.domains.every((domain) => before.domains.some((item) => item.domain === domain));
  const validBodies = [...policy.retainRequestBodies, ...policy.retainResponseBodies].every(
    (index) => Number.isInteger(index) && index >= 0 && index < before.entries.length,
  );
  if (!uniqueDomains || !knownDomains || !validBodies) {
    throw new HarIssue('invalidPolicy');
  }
}

function cleanHarUrl(value, retainPaths) {
  const parsed = url(value);
  if (!parsed) return 'https://redacted.invalid/';
  return `${parsed.origin}${retainPaths ? parsed.pathname : '/[redacted]'}`;
}

function pickAllowedToken(value, allowed, fallback) {
  const candidate = string(value);
  return allowed.has(candidate) ? candidate : fallback;
}

const HTTP_VERSIONS = new Set(['HTTP/1.0', 'HTTP/1.1', 'HTTP/2', 'HTTP/2.0', 'HTTP/3', 'h2', 'h3']);
function cleanHttpVersion(value) {
  return pickAllowedToken(value, HTTP_VERSIONS, '');
}

const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE']);
function cleanHttpMethod(value) {
  return pickAllowedToken(value, HTTP_METHODS, 'GET');
}

function checkHarUnknown(object, allowed, path, remove) {
  if (Object.keys(object).some((key) => !allowed.includes(key))) {
    remove(`${path}/[unknown]`, 'unknownField');
  }
}

function buildSafeRequest(request, policy, keepRequest) {
  const safe = {
    method: cleanHttpMethod(request.method),
    url: cleanHarUrl(request.url, policy.retainPaths),
    httpVersion: cleanHttpVersion(request.httpVersion),
    cookies: [],
    headers: [],
    queryString: [],
    headersSize: -1,
    bodySize: keepRequest ? new TextEncoder().encode(string(record(request.postData).text)).byteLength : 0,
  };
  if (keepRequest) {
    safe.postData = {
      mimeType: mime(record(request.postData).mimeType),
      text: record(request.postData).text,
    };
  }
  return safe;
}

function parseResponseStatus(status) {
  const statusNum = finite(status);
  return Number.isInteger(status) && statusNum >= 100 && statusNum <= 599 ? status : 0;
}

function parseRedirectUrl(redirectURL, policy) {
  const redirectHost = url(redirectURL)?.host ?? '';
  return string(redirectURL) && policy.domains.includes(redirectHost)
    ? cleanHarUrl(redirectURL, policy.retainPaths)
    : '';
}

function buildSafeResponse(response, content, policy, keepResponse) {
  const safeContent = {
    size: finite(content.size, 0),
    mimeType: mime(content.mimeType),
  };
  if (keepResponse) safeContent.text = content.text;

  return {
    status: parseResponseStatus(response.status),
    statusText: '',
    httpVersion: cleanHttpVersion(response.httpVersion),
    cookies: [],
    headers: [],
    content: safeContent,
    redirectURL: parseRedirectUrl(response.redirectURL, policy),
    headersSize: -1,
    bodySize: keepResponse ? new TextEncoder().encode(string(content.text)).byteLength : 0,
  };
}

function buildSafeTimings(rawTimings) {
  const keys = ['blocked', 'dns', 'connect', 'send', 'wait', 'receive', 'ssl'];
  const timings = Object.fromEntries(
    keys.map((key) => [key, finite(rawTimings[key], ['send', 'wait', 'receive'].includes(key) ? 0 : -1)]),
  );
  const total = ['blocked', 'dns', 'connect', 'send', 'wait', 'receive'].reduce(
    (sum, key) => sum + Math.max(0, timings[key]),
    0,
  );
  return { timings, total };
}

function recordHeadersAndCookies(base, request, response, remove) {
  for (const [name, obj] of [['request', request], ['response', response]]) {
    for (const field of ['headers', 'cookies', 'comment']) {
      if (obj[field] !== undefined) remove(`${base}/${name}/${field}`);
    }
    const allowed =
      name === 'request'
        ? ['method', 'url', 'httpVersion', 'cookies', 'headers', 'queryString', 'postData', 'headersSize', 'bodySize', 'comment']
        : ['status', 'statusText', 'httpVersion', 'cookies', 'headers', 'content', 'redirectURL', 'headersSize', 'bodySize', 'comment'];
    checkHarUnknown(obj, allowed, `${base}/${name}`, remove);
  }
}

function recordPayloadRemovals(base, request, content, keepRequest, keepResponse, remove) {
  remove(`${base}/request/url`, 'redacted');
  if (request.queryString !== undefined) remove(`${base}/request/queryString`);
  if (request.postData !== undefined && !keepRequest) remove(`${base}/request/postData`);
  if (keepRequest) checkHarUnknown(record(request.postData), ['mimeType', 'text'], `${base}/request/postData`, remove);
  if (content.text !== undefined && !keepResponse) remove(`${base}/response/content/text`);
  for (const field of ['encoding', 'comment', 'compression']) {
    if (content[field] !== undefined) remove(`${base}/response/content/${field}`);
  }
  checkHarUnknown(content, ['size', 'mimeType', 'text', 'encoding', 'comment', 'compression'], `${base}/response/content`, remove);
}

function recordMetadataRemovals(base, entry, response, rawTimings, originalStart, policy, remove) {
  if (response.redirectURL !== undefined) remove(`${base}/response/redirectURL`, 'redacted');
  if (response.statusText !== undefined) remove(`${base}/response/statusText`);
  for (const field of ['serverIPAddress', 'connection', 'comment', 'pageref', 'cache']) {
    if (entry[field] !== undefined) remove(`${base}/${field}`);
  }
  if (!policy.retainTimes || originalStart === null) remove(`${base}/startedDateTime`, 'redacted');
  checkHarUnknown(entry, ['startedDateTime', 'time', 'request', 'response', 'cache', 'timings', 'serverIPAddress', 'connection', 'comment', 'pageref'], base, remove);
  checkHarUnknown(rawTimings, ['blocked', 'dns', 'connect', 'send', 'wait', 'receive', 'ssl'], `${base}/timings`, remove);
}

function recordEntryRemovals(base, entry, request, response, content, rawTimings, policy, keepRequest, keepResponse, originalStart, remove) {
  recordHeadersAndCookies(base, request, response, remove);
  recordPayloadRemovals(base, request, content, keepRequest, keepResponse, remove);
  recordMetadataRemovals(base, entry, response, rawTimings, originalStart, policy, remove);
}

function checkBodyRetention(request, content, keepRequest, keepResponse) {
  if ((keepRequest && !bodyAllowed(request.postData, false)) || (keepResponse && !bodyAllowed(content, true))) {
    throw new HarIssue('retentionBlocked');
  }
}

function sanitizeLogEntry(value, index, policy, starts, baseline, remove) {
  const entry = record(value);
  const request = record(entry.request);
  const response = record(entry.response);
  const content = record(response.content);
  const base = `/log/entries/${index}`;

  if (!policy.domains.includes(url(request.url)?.host ?? '')) {
    remove(base, 'excludedDomain');
    return null;
  }
  const keepRequest = policy.retainRequestBodies.includes(index);
  const keepResponse = policy.retainResponseBodies.includes(index);
  checkBodyRetention(request, content, keepRequest, keepResponse);

  const safeRequest = buildSafeRequest(request, policy, keepRequest);
  const safeResponse = buildSafeResponse(response, content, policy, keepResponse);
  const rawTimings = record(entry.timings);
  const { timings, total } = buildSafeTimings(rawTimings);

  const originalStart = starts[index];
  const start = new Date(
    originalStart === null ? 0 : policy.retainTimes ? originalStart : originalStart - baseline,
  ).toISOString();

  recordEntryRemovals(base, entry, request, response, content, rawTimings, policy, keepRequest, keepResponse, originalStart, remove);

  return { startedDateTime: start, time: total, request: safeRequest, response: safeResponse, cache: {}, timings };
}

/**
 * Builds a strict zero-secret policy retaining all inspected domains (or a subset)
 * while stripping headers, cookies, queries, IPs, and bodies by default.
 */
export function buildSafeDefaultPolicy(harText, options = {}) {
  const before = inspectHar(harText);
  const available = new Set(before.domains.map((d) => d.domain));
  const domains = options.domains
    ? options.domains.filter((d) => available.has(d))
    : [...available];
  return {
    domains,
    retainPaths: Boolean(options.retainPaths),
    retainTimes: Boolean(options.retainTimes),
    retainRequestBodies: Array.isArray(options.retainRequestBodies) ? options.retainRequestBodies : [],
    retainResponseBodies: Array.isArray(options.retainResponseBodies) ? options.retainResponseBodies : [],
  };
}

/** Whitelist reconstruction: zero spread or copy of source objects into exported HAR. */
export function sanitizeHar(text, policy) {
  const document = parseHarDocument(text);
  const log = record(document.log);
  const before = inspection(log, document);
  validatePolicy(policy, before);

  const removals = [];
  const entries = [];
  const starts = list(log.entries).map((value) => {
    const entry = record(value);
    return policy.domains.includes(url(record(entry.request).url)?.host ?? '')
      ? timestamp(entry.startedDateTime)
      : null;
  });
  const validStarts = starts.filter((start) => start !== null);
  const baseline = validStarts.length ? Math.min(...validStarts) : 0;
  const remove = (path, reason = 'removed') => {
    removals.push({ path, reason });
  };

  checkHarUnknown(document, ['log'], '', remove);
  checkHarUnknown(log, ['version', 'creator', 'entries', 'pages', 'browser', 'comment'], '/log', remove);
  for (const field of ['pages', 'browser', 'comment', 'creator']) {
    if (log[field] !== undefined) remove(`/log/${field}`);
  }

  list(log.entries).forEach((value, index) => {
    const sanitized = sanitizeLogEntry(value, index, policy, starts, baseline, remove);
    if (sanitized) entries.push(sanitized);
  });

  const output = { version: '1.2', creator: { name: 'Sunasty HAR sanitizer', version: '1' }, entries };
  const after = inspection(output, { log: output });
  const summary = buildHarSanitizedSummary(entries);
  return {
    har: JSON.stringify({ log: output }, null, 2),
    before,
    after,
    summary,
    report: {
      format: 'sunasty-har-cleanup-v1',
      entriesBefore: before.entries.length,
      entriesAfter: entries.length,
      removals,
      remainingLocations: after.locations.map(({ path, category }) => ({ path, category })),
      remainingLocationCount: after.totalLocations,
      reviewTruncated: after.totalLocations > after.locations.length,
      policy: {
        selectedDomainCount: policy.domains.length,
        retainPaths: policy.retainPaths,
        retainTimes: policy.retainTimes,
        retainRequestBodies: [...policy.retainRequestBodies],
        retainResponseBodies: [...policy.retainResponseBodies],
      },
      reviewRequired: true,
    },
  };
}

export function harReviewPage(insp, search, page) {
  const matches = insp.locations.filter((item) =>
    `${item.path}\n${item.preview}`.toLowerCase().includes(search.toLowerCase()),
  );
  const pages = Math.max(1, Math.ceil(matches.length / 25));
  const current = Math.max(0, Math.min(page, pages - 1));
  return { locations: matches.slice(current * 25, (current + 1) * 25), page: current, pages, count: matches.length, total: insp.totalLocations };
}

function timingNum(val) {
  return typeof val === 'number' && val > 0 ? val : 0;
}

function buildWaterfallEntry(entry, index) {
  const req = record(entry.request);
  const res = record(entry.response);
  const parsedStart = timestamp(entry.startedDateTime);
  const startMs = parsedStart ?? -1;
  const rawTimings = record(entry.timings);
  const { timings, total } = buildSafeTimings(rawTimings);
  const duration = total > 0 ? total : finite(entry.time, 0);

  return {
    item: {
      index,
      url: string(req.url),
      method: string(req.method) || 'GET',
      status: finite(res.status, 0),
      startTime: parsedStart ?? 0,
      duration,
      timings: {
        blocked: timingNum(timings.blocked),
        dns: timingNum(timings.dns),
        connect: timingNum(timings.connect),
        send: timingNum(timings.send),
        wait: timingNum(timings.wait),
        receive: timingNum(timings.receive),
        ssl: timingNum(timings.ssl),
      },
    },
    startMs,
    duration,
  };
}

function computeWaterfallFromEntries(rawEntries) {
  let earliestStart = Infinity;
  let latestEnd = -Infinity;
  const waterfallEntries = [];

  rawEntries.forEach((value, index) => {
    const { item, startMs, duration } = buildWaterfallEntry(record(value), index);
    if (startMs >= 0) {
      if (startMs < earliestStart) earliestStart = startMs;
      if (startMs + duration > latestEnd) latestEnd = startMs + duration;
    }
    waterfallEntries.push(item);
  });

  const valid = earliestStart !== Infinity;
  return {
    totalDuration: valid ? Math.max(0, latestEnd - earliestStart) : 0,
    earliestStart: valid ? earliestStart : 0,
    latestEnd: valid ? latestEnd : 0,
    entries: waterfallEntries,
  };
}

export function computeParsedWaterfallSummary(document) {
  const log = record(document.log);
  return computeWaterfallFromEntries(list(log.entries));
}

export function computeWaterfallSummary(text) {
  return computeParsedWaterfallSummary(parseHarDocument(text));
}

function buildHarSanitizedSummary(entries) {
  const wf = computeWaterfallFromEntries(entries);
  let payloadsCount = 0;
  for (const entry of entries) {
    const content = record(record(entry.response).content);
    if (typeof content.text === 'string' && content.text.length > 0) payloadsCount += 1;
  }
  const topEntries = wf.entries.slice(0, 5).map((item) => ({
    ...item,
    curl: generateCurlCommand(entries[item.index]),
  }));
  return { wf, payloadsCount, topEntries };
}

export function generateCurlCommand(entryValue) {
  const entry = record(entryValue);
  const req = record(entry.request);
  const targetUrl = string(req.url);
  if (!targetUrl) return '';

  const method = string(req.method) || 'GET';
  const parts = [`curl -X ${method} '${targetUrl.replace(/'/g, "'\\''")}'`];

  for (const h of list(req.headers)) {
    const headerObj = record(h);
    const name = string(headerObj.name);
    const value = string(headerObj.value);
    if (name) parts.push(`-H '${name}: ${value.replace(/'/g, "'\\''")}'`);
  }

  const postData = record(req.postData);
  if (postData.text && typeof postData.text === 'string') {
    parts.push(`--data-raw '${postData.text.replace(/'/g, "'\\''")}'`);
  }

  return parts.join(' \\\n  ');
}

export function extractParsedResponsePayloads(document) {
  const log = record(document.log);
  const entries = list(log.entries);
  const payloads = [];

  entries.forEach((value, index) => {
    const entry = record(value);
    const response = record(entry.response);
    const content = record(response.content);
    const textVal = typeof content.text === 'string' ? content.text : undefined;
    payloads.push({
      index,
      mimeType: mime(content.mimeType),
      size: finite(content.size, 0),
      ...(content.encoding ? { encoding: string(content.encoding) } : {}),
      ...(textVal !== undefined ? { text: textVal } : {}),
    });
  });

  return payloads;
}

export function extractResponsePayloads(text) {
  return extractParsedResponsePayloads(parseHarDocument(text));
}
