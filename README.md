# @sunasty/har-sanitizer

Zero-dependency HAR 1.2 whitelist sanitizer, forensic privacy inspector, waterfall timing analyzer, and cURL generator with a built-in CLI (`npx @sunasty/har-sanitizer`).

Extracted from the core engine powering the browser-local [Sunasty HAR Sanitizer](https://sunasty.com/har-sanitizer/) and the [Sunasty Developer & Security Suite](https://sunasty.com/dev/).

## Installation

```bash
npm install @sunasty/har-sanitizer
# or via JSR
npx jsr add @sunasty/har-sanitizer
```

## Features

- **Whitelist Reconstruction**: Builds a clean HAR 1.2 archive from scratch without copying cookies, `Authorization` headers, API keys, query strings, `Set-Cookie` values, server IPs, browser metadata, or unknown custom keys.
- **Forensic Location Inventory**: `inspectHar` maps domains and every sensitive URL, header, cookie, body, and metadata path before sanitizing.
- **Bounded JSON Validator**: Rejects duplicate property shadowing, extreme nesting depth, and malformed numeric exponents before serialization.
- **Zero-Dependency CLI**: Strip sensitive HAR traces straight from the terminal or CI pipelines using `npx @sunasty/har-sanitizer` (or `har-sanitizer` when installed).
- **Waterfall & cURL Helpers**: Computes relative timings (`computeWaterfallSummary`), payload metadata (`extractResponsePayloads`), and reproducible cURL commands (`generateCurlCommand`).

## CLI Usage

```bash
npx @sunasty/har-sanitizer trace.har -o clean.har
npx @sunasty/har-sanitizer trace.har --retain-paths --domains api.example.com --report audit.json -o clean.har
npx @sunasty/har-sanitizer trace.har --inspect
```

## Programmatic Usage

```js
import { inspectHar, buildSafeDefaultPolicy, sanitizeHar } from '@sunasty/har-sanitizer';

const inspection = inspectHar(harJsonString);
console.log(inspection.domains);

const policy = buildSafeDefaultPolicy(harJsonString, {
  retainPaths: true,
  retainTimes: false,
});

const result = sanitizeHar(harJsonString, policy);
console.log(result.har);
console.log(result.report.removals.length);
```

## Related Web Tools

- Interactive client-side HAR inspector and sanitizer: [https://sunasty.com/har-sanitizer/](https://sunasty.com/har-sanitizer/)
- Privacy and developer browser tools: [https://sunasty.com/dev/](https://sunasty.com/dev/)

## License

MIT
