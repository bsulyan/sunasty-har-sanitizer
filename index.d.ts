export declare const HAR_MAX_BYTES: number;
export declare const HAR_MAX_ENTRIES: number;
export declare const HAR_LIMITS: { bytes: number; entries: number; decodedBytes: number };
export type HarIssueCode = 'invalidHar' | 'tooManyEntries' | 'invalidPolicy' | 'retentionBlocked';
export declare class HarIssue extends Error {
  code: HarIssueCode;
  constructor(code: HarIssueCode);
}
export interface HarPolicy {
  domains: string[];
  retainPaths: boolean;
  retainTimes: boolean;
  retainRequestBodies: number[];
  retainResponseBodies: number[];
}
export interface HarLocation {
  path: string;
  category: 'url' | 'header' | 'cookie' | 'body' | 'metadata' | 'unknown';
  preview: string;
  retained: boolean;
}
export interface HarDomain {
  domain: string;
  entries: number;
}
export interface HarEntryPreview {
  index: number;
  domain: string;
  method: string;
  requestBodyAllowed: boolean;
  responseBodyAllowed: boolean;
}
export interface HarInspection {
  domains: HarDomain[];
  entries: HarEntryPreview[];
  locations: HarLocation[];
  totalLocations: number;
}
export interface HarRemoval {
  path: string;
  reason: 'removed' | 'redacted' | 'excludedDomain' | 'unknownField';
}
export interface HarReport {
  format: 'sunasty-har-cleanup-v1';
  entriesBefore: number;
  entriesAfter: number;
  removals: HarRemoval[];
  remainingLocations: { path: string; category: HarLocation['category'] }[];
  remainingLocationCount: number;
  reviewTruncated: boolean;
  policy: Omit<HarPolicy, 'domains'> & { selectedDomainCount: number };
  reviewRequired: true;
}
export interface HarWaterfallTiming {
  index: number;
  url: string;
  method: string;
  status: number;
  startTime: number;
  duration: number;
  timings: {
    blocked: number;
    dns: number;
    connect: number;
    send: number;
    wait: number;
    receive: number;
    ssl: number;
  };
}
export interface HarWaterfallSummary {
  totalDuration: number;
  earliestStart: number;
  latestEnd: number;
  entries: HarWaterfallTiming[];
}
export interface HarTopCurlEntry extends HarWaterfallTiming {
  curl: string;
}
export interface HarSanitizedSummary {
  wf: HarWaterfallSummary;
  payloadsCount: number;
  topEntries: HarTopCurlEntry[];
}
export interface HarResult {
  har: string;
  report: HarReport;
  before: HarInspection;
  after: HarInspection;
  summary: HarSanitizedSummary;
}
export interface ExtractedPayload {
  index: number;
  mimeType: string;
  size: number;
  encoding?: string;
  text?: string;
}
export declare function parseHarDocument(text: string): Record<string, unknown>;
export declare function inspectParsedHar(document: Record<string, unknown>): HarInspection;
export declare function inspectHar(text: string): HarInspection;
export declare function buildSafeDefaultPolicy(
  harText: string,
  options?: {
    domains?: string[];
    retainPaths?: boolean;
    retainTimes?: boolean;
    retainRequestBodies?: number[];
    retainResponseBodies?: number[];
  }
): HarPolicy;
export declare function sanitizeHar(text: string, policy: HarPolicy): HarResult;
export declare function harReviewPage(
  inspection: HarInspection,
  search: string,
  page: number
): { locations: HarLocation[]; page: number; pages: number; count: number; total: number };
export declare function computeParsedWaterfallSummary(document: Record<string, unknown>): HarWaterfallSummary;
export declare function computeWaterfallSummary(text: string): HarWaterfallSummary;
export declare function generateCurlCommand(entryValue: unknown): string;
export declare function extractParsedResponsePayloads(document: Record<string, unknown>): ExtractedPayload[];
export declare function extractResponsePayloads(text: string): ExtractedPayload[];
