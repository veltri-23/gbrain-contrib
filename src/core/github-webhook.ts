import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Response } from 'express';
import { isValidRepoName } from './github-source.ts';
import { safeHexEqual } from './timing-safe.ts';
import { MinionQueue } from './minions/queue.ts';
import type { BrainEngine } from './engine.ts';

/**
 * v0.46: issue/PR webhook handling for github-kind sources. Extracted from
 * serve-http.ts so the HTTP server stays under its module-size ratchet;
 * the machine is behaviour-identical to the inline v0.46 itemFlow.
 */

/** Event types that carry a single-item (repo + number) reference. */
export const GH_ITEM_EVENTS = new Set([
  'issues',
  'pull_request',
  'issue_comment',
  'pull_request_review',
  'pull_request_review_comment',
  'label',
  'assignee',
  'milestone',
  'check_run',
  'check_suite',
  'workflow_run',
]);

/**
 * Normalize the per-event GitHub webhook payload shape into
 * {repo, number, kind}. Events differ: issues/issue_comment/label/
 * assignee/milestone carry a top-level `issue` (PRs appear there too,
 * flagged by `issue.pull_request`), pull_request/review events carry
 * top-level `pull_request`, and check events nest the linked PRs under
 * check_run/check_suite/workflow_run. Returns null when the payload
 * carries no item reference (ping, branch, non-PR checks).
 */
export function extractGitHubItemRef(parsed: Record<string, unknown>): { repo: string; number: number; kind: 'issue' | 'pr' } | null {
  const repoObj = parsed.repository as { full_name?: string } | undefined;
  const repo = repoObj?.full_name ?? '';
  const issueObj = parsed.issue as { number?: number; pull_request?: unknown } | undefined;
  const prObj = parsed.pull_request as { number?: number } | undefined;
  const checkRun = parsed.check_run as { pull_requests?: Array<{ number?: number }> } | undefined;
  const checkSuite = parsed.check_suite as { pull_requests?: Array<{ number?: number }> } | undefined;
  const workflowRun = parsed.workflow_run as { pull_requests?: Array<{ number?: number }> } | undefined;
  const nestedPrNumber =
    checkRun?.pull_requests?.[0]?.number ??
    checkSuite?.pull_requests?.[0]?.number ??
    workflowRun?.pull_requests?.[0]?.number;
  const number = prObj?.number ?? issueObj?.number ?? nestedPrNumber;
  if (typeof number !== 'number' || !isValidRepoName(repo)) return null;
  const kind = prObj !== undefined || issueObj?.pull_request !== undefined || nestedPrNumber !== undefined ? 'pr' : 'issue';
  return { repo, number, kind };
}

function verifyWebhookSig(cfg: Record<string, unknown>, sigHeader: string, payload: Buffer): boolean {
  const secret = cfg.webhook_secret;
  if (typeof secret !== 'string' || secret === '') return false;
  // Strict hex shape first: a malformed 64-char signature would make
  // safeHexEqual throw (500 instead of 401).
  if (!/^sha256=[0-9a-f]{64}$/.test(sigHeader)) return false;
  const computedHex = createHmac('sha256', secret).update(payload).digest('hex');
  return safeHexEqual(sigHeader.slice('sha256='.length), computedHex);
}

function githubKindCoversRepo(
  cfg: Record<string, unknown>,
  localPath: string | null,
  fullName: string,
): boolean {
  if (cfg.gh_scope === 'repos') {
    const repos = typeof cfg.gh_repos === 'string' ? cfg.gh_repos.split(',').map((s) => s.trim()) : [];
    return repos.includes(fullName);
  }
  // auto scope: honor the last discovery (state file). Without state yet,
  // accept and let the sync engine's own scope re-check decide.
  if (localPath) {
    try {
      const state = JSON.parse(readFileSync(join(localPath, '.github-source.json'), 'utf-8')) as {
        repos?: string[];
      };
      if (Array.isArray(state.repos)) return state.repos.includes(fullName);
    } catch {
      /* no state yet */
    }
  }
  return true;
}

/**
 * v0.46: handle an issue/PR webhook event for github-kind sources. The
 * payload names a single item (repo + number); we verify the per-source
 * HMAC and submit a targeted `sync` job with github_item so exactly that
 * item is refreshed. Out-of-scope repos are rejected at queue time by
 * the sync engine's own scope check.
 */
export async function handleGitHubItemEvent(
  engine: BrainEngine,
  parsed: Record<string, unknown>,
  sigHeader: string,
  payload: Buffer,
  res: Response,
  eventName: string,
): Promise<void> {
  const ref = extractGitHubItemRef(parsed);
  if (ref === null) {
    // Not an item-bearing payload (e.g. check events without a linked PR,
    // ping, branch protection). Acknowledge so GitHub does not retry.
    res.status(202).json({ status: 'ignored', reason: 'no_item_ref' });
    return;
  }

  // Collect ALL candidate sources: exact github_repo matches (legacy
  // webhook config) and github-kind sources with a webhook secret, then
  // verify HMAC per candidate. First valid HMAC wins; two valid matches
  // mean ambiguous configuration and must not pick silently.
  let source: { id: string; local_path: string | null; config: unknown } | null = null;
  try {
    const rows = await engine.executeRaw<{ id: string; local_path: string | null; config: unknown }>(
      `SELECT id, local_path, config FROM sources
         WHERE archived = false
           AND ((config->>'github_repo' = $1)
             OR (config->>'kind' = 'github' AND config->>'webhook_secret' IS NOT NULL))`,
      [ref.repo],
    );
    const verified: { id: string; local_path: string | null; config: unknown }[] = [];
    for (const row of rows) {
      const cfg = (typeof row.config === 'string' ? JSON.parse(row.config) : (row.config ?? {})) as Record<string, unknown>;
      if (cfg.github_repo === ref.repo && verifyWebhookSig(cfg, sigHeader, payload)) {
        verified.push(row);
        continue;
      }
      if (cfg.kind === 'github' && githubKindCoversRepo(cfg, row.local_path, ref.repo) && verifyWebhookSig(cfg, sigHeader, payload)) {
        verified.push(row);
      }
    }
    if (verified.length > 1) {
      res.status(500).json({
        error: 'ambiguous_webhook',
        message: `multiple sources verified the signature for ${ref.repo}; configure one webhook secret per source`,
        sources: verified.map((v) => v.id),
      });
      return;
    }
    source = verified[0] ?? null;
  } catch (err) {
    console.error('webhook: github-kind source lookup error:', err);
    res.status(500).json({ error: 'lookup_failed' });
    return;
  }
  if (!source) {
    res.status(404).json({ error: 'unknown_repo', repo: ref.repo });
    return;
  }

  try {
    const queue = new MinionQueue(engine);
    const job = await queue.add(
      'sync',
      {
        sourceId: source.id,
        noExtract: false,
        github_item: {
          repo: ref.repo,
          number: ref.number,
          kind: ref.kind,
          ...(eventName === 'issues' && parsed.action === 'deleted' ? { deleted: true } : {}),
        },
        embed_reason: 'webhook',
      },
      {
        priority: -10,
        idempotency_key: `webhook:item:${source.id}:${ref.repo}:${ref.number}:${Math.floor(Date.now() / 30_000)}`,
        maxWaiting: 1,
      },
    );
    res.status(202).json({ job_id: job.id, source_id: source.id, item: ref });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('webhook: item queue submission error:', msg);
    res.status(500).json({ error: 'queue_submission_failed', message: msg });
  }
}
