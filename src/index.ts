import * as core from '@actions/core';

interface ScanInitiateResponse {
  status: number;
  code?: string;
  url?: string;
  message?: string;
}

interface ScanStatusResponse {
  scanStatus: number;
  message?: string;
}

// scanStatus values >= this threshold indicate the scan has finished, per the ZeroThreat API.
const SCAN_COMPLETED_THRESHOLD = 4;

const DEFAULT_POLL_INTERVAL_SECONDS = 300; // 5 minutes
const DEFAULT_MAX_WAIT_MINUTES = 60;
const REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_INITIATE_RETRIES = 3;
const RETRY_BASE_DELAY_MS = 1_000; // backs off 1s, 2s, 4s, ...

class ApiError extends Error {
  constructor(message: string, public readonly status?: number) {
    super(message);
    this.name = 'ApiError';
  }
}

/**
 * Decides whether a failure is worth retrying.
 *
 * Retryable: no HTTP status at all (network error, DNS failure, our own
 * timeout), 429 (rate limited), or any 5xx (server-side problem, including
 * 503 Service Unavailable).
 *
 * Not retryable: any other 4xx. Those mean the request itself was rejected
 * (bad token, bad payload, etc.) — retrying sends the exact same request and
 * will just fail the same way again.
 */
function isRetryableError(err: unknown): boolean {
  if (!(err instanceof ApiError)) return false;
  if (err.status === undefined) return true;
  return err.status === 429 || err.status >= 500;
}

/**
 * Retries fn with exponential backoff, but only for errors classified as
 * retryable by isRetryableError. maxRetries is the number of retries on
 * top of the initial attempt (maxRetries=3 means up to 4 attempts total).
 */
async function withRetry<T>(fn: () => Promise<T>, maxRetries: number): Promise<T> {
  let lastError: unknown;

  for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      const attemptsRemaining = maxRetries + 1 - attempt;

      if (attemptsRemaining <= 0 || !isRetryableError(err)) {
        throw err;
      }

      const delayMs = RETRY_BASE_DELAY_MS * 2 ** (attempt - 1);
      core.warning(
        `Attempt ${attempt}/${maxRetries + 1} to start the scan failed (${err instanceof Error ? err.message : String(err)
        }). Retrying in ${delayMs / 1000}s...`
      );
      await sleep(delayMs);
    }
  }

  throw lastError;
}

/**
 * Thin fetch wrapper: applies a timeout, parses JSON safely, and — unlike raw
 * fetch — throws on non-2xx responses with the API's own error message
 * surfaced (instead of just "Request failed with status code 400").
 */
async function fetchJson<T>(url: string, options: RequestInit = {}): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  let response: Response;
  try {
    response = await fetch(url, { ...options, signal: controller.signal });
  } catch (err) {
    if (err instanceof Error && err.name === 'AbortError') {
      throw new ApiError(`Request to ${url} timed out after ${REQUEST_TIMEOUT_MS / 1000}s`);
    }
    throw new ApiError(`Network error calling ${url}: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    clearTimeout(timeout);
  }

  const rawBody = await response.text();
  let parsedBody: any = undefined;
  if (rawBody) {
    try {
      parsedBody = JSON.parse(rawBody);
    } catch {
      // Response wasn't JSON — fall back to raw text below for error reporting.
    }
  }

  if (!response.ok) {
    const apiMessage = parsedBody?.message ?? parsedBody?.error ?? rawBody ?? response.statusText;
    throw new ApiError(`Request to ${url} failed (${response.status}): ${apiMessage}`, response.status);
  }

  return (parsedBody ?? {}) as T;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function buildApiBaseUrl(onPremProxyUrl: string): string {
  const base = onPremProxyUrl?.trim() || 'https://api.zerothreat.ai';
  try {
    new URL(base); // validates the URL is well-formed; throws otherwise
  } catch {
    throw new Error(`ON_PREM_PROXY_API_URL is not a valid URL: "${base}"`);
  }
  return base.replace(/\/+$/, ''); // strip trailing slash
}

/**
 * Polls the scan status endpoint until the scan completes or maxWaitMs elapses.
 * Uses a plain await/sleep loop (not setInterval) so the process exits cleanly
 * as soon as the loop is done, and so a slow/stuck scan can't hang the job forever.
 */
async function pollScanStatus(statusUrl: string, pollIntervalMs: number, maxWaitMs: number): Promise<void> {
  const deadline = Date.now() + maxWaitMs;

  while (true) {
    const status = await withRetry(
      () => fetchJson<ScanStatusResponse>(statusUrl),
      DEFAULT_INITIATE_RETRIES
    ).catch((err) => {
      throw new Error(`Status polling failed: ${err instanceof Error ? err.message : String(err)}`);
    });

    if (status.scanStatus >= SCAN_COMPLETED_THRESHOLD) {
      core.info('Scan completed successfully.');
      core.setOutput('scan-status', String(status.scanStatus));
      return;
    }

    if (Date.now() >= deadline) {
      throw new Error(`Timed out after ${Math.round(maxWaitMs / 60000)} minute(s) waiting for scan to complete.`);
    }

    core.info(`Scan is in progress [${new Date().toISOString()}]. Checking again in ${pollIntervalMs / 1000}s.`);
    await sleep(pollIntervalMs);
  }
}

async function run(): Promise<void> {
  try {
    const token = core.getInput('ZT_TOKEN', { required: true });
    core.setSecret(token); // ensure the token is masked in logs, even under debug output

    const onPremProxyUrl = core.getInput('ON_PREM_PROXY_API_URL', { required: false });
    const waitForAnalysis = core.getInput('WAIT_FOR_ANALYSIS', { required: false }).toLowerCase() === 'true';
    const pollIntervalSeconds =
      Number(core.getInput('POLL_INTERVAL_SECONDS', { required: false })) || DEFAULT_POLL_INTERVAL_SECONDS;
    const maxWaitMinutes =
      Number(core.getInput('MAX_WAIT_MINUTES', { required: false })) || DEFAULT_MAX_WAIT_MINUTES;

    const apiBase = buildApiBaseUrl(onPremProxyUrl);
    const initiateUrl = `${apiBase}/api/scan/devops`;

    core.info('Initiating security scan request...');

    const initiateResponse = await withRetry(
      () =>
        fetchJson<ScanInitiateResponse>(initiateUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token }),
        }),
      DEFAULT_INITIATE_RETRIES
    );

    if (initiateResponse.status !== 200) {
      core.setFailed(`Scan failed to start. Reason: ${initiateResponse.message ?? 'Unknown error from ZeroThreat API'}`);
      return; // stop here — without this, execution used to fall through to status polling with no scan running
    }

    core.info(`Scan started successfully. Scan Report URL: ${initiateResponse.url}`);
    core.setOutput('scan-url', initiateResponse.url ?? '');
    core.setOutput('scan-code', initiateResponse.code ?? '');

    if (!waitForAnalysis) {
      return;
    }

    if (!initiateResponse.code) {
      core.setFailed('WAIT_FOR_ANALYSIS is true but the API did not return a scan code to poll.');
      return;
    }

    await pollScanStatus(`${initiateUrl}/${initiateResponse.code}`, pollIntervalSeconds * 1000, maxWaitMinutes * 60 * 1000);
  } catch (error) {
    core.setFailed(`Action failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

run();