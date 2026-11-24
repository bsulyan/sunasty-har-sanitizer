import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { writeFileSync, unlinkSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  inspectHar,
  buildSafeDefaultPolicy,
  sanitizeHar,
  computeWaterfallSummary,
  generateCurlCommand,
  extractResponsePayloads,
  HarIssue,
} from './index.js';

const SAMPLE_HAR = JSON.stringify({
  log: {
    version: '1.2',
    creator: { name: 'Chrome', version: '136' },
    browser: { name: 'Chrome', version: '136' },
    entries: [
      {
        startedDateTime: '2026-11-24T10:00:00.000Z',
        time: 42,
        serverIPAddress: '192.0.2.10',
        request: {
          method: 'POST',
          url: 'https://api.example.com/v1/login?token=secret_query',
          httpVersion: 'HTTP/2',
          headers: [{ name: 'Authorization', value: 'Bearer secret_jwt' }],
          cookies: [{ name: 'session', value: 'abc123' }],
          queryString: [{ name: 'token', value: 'secret_query' }],
          postData: { mimeType: 'application/json', text: '{"password":"123"}' },
        },
        response: {
          status: 200,
          statusText: 'OK',
          httpVersion: 'HTTP/2',
          headers: [{ name: 'Set-Cookie', value: 'session=abc123' }],
          cookies: [{ name: 'session', value: 'abc123' }],
          content: { size: 12, mimeType: 'application/json', text: '{"ok":true}' },
          redirectURL: 'https://secret.other.com/cb',
        },
        timings: { blocked: 1, dns: 2, connect: 3, send: 4, wait: 25, receive: 7, ssl: 2 },
      },
      {
        startedDateTime: '2026-11-24T10:00:05.000Z',
        time: 10,
        request: { method: 'GET', url: 'https://tracker.ads.example/pixel.png', httpVersion: 'HTTP/2', headers: [], cookies: [] },
        response: { status: 204, statusText: 'No Content', httpVersion: 'HTTP/2', headers: [], cookies: [], content: { size: 0, mimeType: 'image/png' } },
        timings: { send: 1, wait: 8, receive: 1 },
      },
    ],
  },
});

test('inspectHar and sanitizeHar strip headers, cookies, queries, IPs, and excluded domains', () => {
  const before = inspectHar(SAMPLE_HAR);
  assert.equal(before.entries.length, 2);
  assert.equal(before.domains.length, 2);

  const policy = buildSafeDefaultPolicy(SAMPLE_HAR, { domains: ['api.example.com'], retainPaths: false, retainTimes: false });
  const result = sanitizeHar(SAMPLE_HAR, policy);

  assert.equal(result.report.entriesBefore, 2);
  assert.equal(result.report.entriesAfter, 1);

  const parsed = JSON.parse(result.har);
  const entry = parsed.log.entries[0];
  assert.equal(entry.request.url, 'https://api.example.com/[redacted]');
  assert.deepEqual(entry.request.headers, []);
  assert.deepEqual(entry.request.cookies, []);
  assert.deepEqual(entry.response.headers, []);
  assert.equal(entry.response.content.text, undefined);
  assert.equal(entry.serverIPAddress, undefined);
  assert.equal(entry.startedDateTime, '1970-01-01T00:00:00.000Z');
});

test('waterfall, payloads, cURL generation, and error bounds', () => {
  const wf = computeWaterfallSummary(SAMPLE_HAR);
  assert.equal(wf.entries.length, 2);
  assert.ok(wf.totalDuration >= 5000);

  const payloads = extractResponsePayloads(SAMPLE_HAR);
  assert.equal(payloads[0].text, '{"ok":true}');

  const curl = generateCurlCommand(JSON.parse(SAMPLE_HAR).log.entries[0]);
  assert.match(curl, /curl -X POST/);

  assert.throws(() => inspectHar('{"log":{"version":"1.0","entries":[]}}'), (e) => e instanceof HarIssue && e.code === 'invalidHar');
});

test('CLI sanitizes HAR file to output file with audit report', () => {
  const tmpIn = join(tmpdir(), `har-in-${Date.now()}.har`);
  const tmpOut = join(tmpdir(), `har-out-${Date.now()}.har`);
  const tmpRep = join(tmpdir(), `har-rep-${Date.now()}.json`);
  try {
    writeFileSync(tmpIn, SAMPLE_HAR, 'utf8');
    execFileSync(process.execPath, ['bin/cli.js', tmpIn, '-o', tmpOut, '--domains', 'api.example.com', '--retain-paths', '--report', tmpRep]);
    const sanitized = JSON.parse(readFileSync(tmpOut, 'utf8'));
    const report = JSON.parse(readFileSync(tmpRep, 'utf8'));
    assert.equal(sanitized.log.entries.length, 1);
    assert.equal(sanitized.log.entries[0].request.url, 'https://api.example.com/v1/login');
    assert.equal(report.entriesAfter, 1);
  } finally {
    for (const f of [tmpIn, tmpOut, tmpRep]) {
      try { unlinkSync(f); } catch {}
    }
  }
});
