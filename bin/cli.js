#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { inspectHar, buildSafeDefaultPolicy, sanitizeHar } from '../index.js';

function printHelp() {
  console.log(`har-clean v1.0.0

Usage:
  har-clean <input.har | -> [options]

Options:
  -o, --out <file>         Write sanitized HAR JSON to <file> (default: stdout)
  --domains <list>         Comma-separated hostnames to retain (default: all)
  --retain-paths           Keep URL pathnames (query strings are always stripped)
  --retain-times           Keep original ISO timestamps instead of rebasing to epoch
  --inspect                Print forensic inspection summary JSON instead of sanitizing
  --report <file>          Write JSON audit report of removed/redacted paths
  -h, --help               Show this help message
  -v, --version            Print version`);
}

function parseCliArgs(argv) {
  const opts = { input: '', out: '', domains: null, retainPaths: false, retainTimes: false, inspect: false, report: '', help: false, version: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '-h' || arg === '--help') opts.help = true;
    else if (arg === '-v' || arg === '--version') opts.version = true;
    else if (arg === '--retain-paths') opts.retainPaths = true;
    else if (arg === '--retain-times') opts.retainTimes = true;
    else if (arg === '--inspect') opts.inspect = true;
    else if ((arg === '-o' || arg === '--out') && argv[i + 1]) opts.out = argv[++i];
    else if (arg === '--report' && argv[i + 1]) opts.report = argv[++i];
    else if (arg === '--domains' && argv[i + 1]) opts.domains = argv[++i].split(',').map((s) => s.trim()).filter(Boolean);
    else if (arg.startsWith('--domains=')) opts.domains = arg.slice(10).split(',').map((s) => s.trim()).filter(Boolean);
    else if (!opts.input) opts.input = arg;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return opts;
}

function main() {
  const opts = parseCliArgs(process.argv.slice(2));
  if (opts.version) { console.log('1.0.0'); return; }
  if (opts.help || !opts.input) { printHelp(); process.exit(opts.help ? 0 : 1); }

  const raw = opts.input === '-' ? readFileSync(0, 'utf8') : readFileSync(opts.input, 'utf8');
  if (opts.inspect) {
    const insp = inspectHar(raw);
    const outText = JSON.stringify(insp, null, 2) + '\n';
    if (opts.out) writeFileSync(opts.out, outText, 'utf8');
    else process.stdout.write(outText);
    return;
  }

  const policy = buildSafeDefaultPolicy(raw, {
    domains: opts.domains ?? undefined,
    retainPaths: opts.retainPaths,
    retainTimes: opts.retainTimes,
  });
  const result = sanitizeHar(raw, policy);
  if (opts.report) {
    writeFileSync(opts.report, JSON.stringify(result.report, null, 2) + '\n', 'utf8');
  }
  if (opts.out) {
    writeFileSync(opts.out, result.har + '\n', 'utf8');
    console.error(`Sanitized ${result.report.entriesAfter}/${result.report.entriesBefore} entries (${result.report.removals.length} removals) -> ${opts.out}`);
  } else {
    process.stdout.write(result.har + '\n');
  }
}

try {
  main();
} catch (err) {
  console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
