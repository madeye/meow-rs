export const meta = {
  name: 'cleanup-issues-prs',
  description: 'Triage open GitHub issues and PRs: flag fixed/stale/duplicate issues and stuck PRs, report recommendations, optionally apply them',
  whenToUse: 'Run when the issue/PR backlog needs grooming. Dry-run by default — produces a recommendation report. Pass {apply: true} as args to actually close issues and post comments (PRs are never auto-merged or auto-closed).',
  phases: [
    { title: 'Inventory', detail: 'fetch open issues and PRs via gh' },
    { title: 'Triage', detail: 'one agent per issue/PR investigates and recommends an action' },
    { title: 'Apply', detail: 'execute high-confidence issue closes/comments (only with args.apply)' },
  ],
}

const INVENTORY_SCHEMA = {
  type: 'object',
  required: ['repo', 'issues', 'prs'],
  properties: {
    repo: { type: 'string', description: 'owner/name' },
    issues: {
      type: 'array',
      items: {
        type: 'object',
        required: ['number', 'title', 'updatedAt'],
        properties: {
          number: { type: 'number' },
          title: { type: 'string' },
          updatedAt: { type: 'string' },
          labels: { type: 'array', items: { type: 'string' } },
        },
      },
    },
    prs: {
      type: 'array',
      items: {
        type: 'object',
        required: ['number', 'title', 'author', 'updatedAt'],
        properties: {
          number: { type: 'number' },
          title: { type: 'string' },
          author: { type: 'string' },
          updatedAt: { type: 'string' },
          isDraft: { type: 'boolean' },
        },
      },
    },
  },
}

const ISSUE_REC_SCHEMA = {
  type: 'object',
  required: ['number', 'action', 'confidence', 'reason'],
  properties: {
    number: { type: 'number' },
    action: {
      type: 'string',
      enum: ['close-fixed', 'close-stale', 'close-duplicate', 'comment', 'keep'],
    },
    confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    reason: { type: 'string', description: 'one-paragraph justification with evidence (commit SHAs, PR numbers, file paths)' },
    comment: { type: 'string', description: 'the exact comment to post when closing or commenting; empty for keep' },
  },
}

const PR_REC_SCHEMA = {
  type: 'object',
  required: ['number', 'action', 'confidence', 'reason'],
  properties: {
    number: { type: 'number' },
    action: {
      type: 'string',
      enum: ['merge-ready', 'needs-rebase', 'needs-review', 'superseded', 'stale-ping', 'keep'],
    },
    confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    reason: { type: 'string', description: 'justification: CI state, mergeability, conflicts, linked issues' },
    comment: { type: 'string', description: 'comment to post on the PR when action is stale-ping or superseded; empty otherwise' },
  },
}

const APPLY_SCHEMA = {
  type: 'object',
  required: ['number', 'executed', 'detail'],
  properties: {
    number: { type: 'number' },
    executed: { type: 'boolean' },
    detail: { type: 'string' },
  },
}

phase('Inventory')
const inv = await agent(
  `Run gh to inventory the current repository's open items. Use:
  - gh repo view --json nameWithOwner
  - gh issue list --state open --limit 200 --json number,title,updatedAt,labels
  - gh pr list --state open --limit 200 --json number,title,updatedAt,isDraft,author
Return the repo slug plus the full lists. Flatten labels to their name strings and author to its login string.`,
  { label: 'inventory', phase: 'Inventory', schema: INVENTORY_SCHEMA }
)
if (!inv) throw new Error('inventory agent failed — is gh authenticated?')
log(`${inv.repo}: ${inv.issues.length} open issues, ${inv.prs.length} open PRs`)

const issueRecs = pipeline(
  inv.issues,
  (i) =>
    agent(
      `You are triaging open issue #${i.number} in ${inv.repo}: "${i.title}" (last updated ${i.updatedAt}).
Investigate whether this issue is still actionable:
1. gh issue view ${i.number} --repo ${inv.repo} --comments — read the full thread.
2. Search for an open or merged PR that addresses it: gh pr list --repo ${inv.repo} --search "${i.number}" --state all, and check git log / the current code on main for evidence the problem is already fixed.
3. Check the other open issues (gh issue list) for duplicates.
Recommend exactly one action:
- close-fixed: the fix is already merged to main (cite the commit/PR)
- close-stale: no activity for >90 days, not reproducible, or reporter never followed up after a request for info
- close-duplicate: another open issue covers it (cite the number)
- comment: still valid but needs a status update or a question posted
- keep: valid and actionable as-is
Be conservative: when evidence is incomplete, prefer keep or comment with confidence low/medium. Write the comment field as the exact GitHub comment text to post (for any close-* or comment action), professional and specific.`,
      { label: `issue#${i.number}`, phase: 'Triage', schema: ISSUE_REC_SCHEMA }
    )
)

const prRecs = pipeline(
  inv.prs,
  (p) =>
    agent(
      `You are triaging open PR #${p.number} in ${inv.repo} by ${p.author}: "${p.title}" (last updated ${p.updatedAt}${p.isDraft ? ', draft' : ''}).
Investigate its state:
1. gh pr view ${p.number} --repo ${inv.repo} --json state,mergeable,mergeStateStatus,reviewDecision,statusCheckRollup,body,comments
2. gh pr diff ${p.number} --repo ${inv.repo} | head -300 — skim the change.
3. Check whether main already contains an equivalent change (git log --oneline -30, search the touched files), which would make it superseded.
Recommend exactly one action:
- merge-ready: CI green, no conflicts, approved or trivially reviewable — a human should merge it
- needs-rebase: has merge conflicts or is behind main with failing/stale checks
- needs-review: CI green but awaiting review
- superseded: an equivalent change already landed on main (cite the commit)
- stale-ping: external contribution with no activity for >30 days awaiting author action — post a polite ping
- keep: fine as-is, no action needed
NEVER recommend merging or closing automatically — these recommendations go to a human. Fill the comment field only for stale-ping/superseded with the exact text to post.`,
      { label: `pr#${p.number}`, phase: 'Triage', schema: PR_REC_SCHEMA }
    )
)

const [issues, prs] = await parallel([() => issueRecs, () => prRecs])
const issueResults = (issues || []).filter(Boolean)
const prResults = (prs || []).filter(Boolean)
log(`triage done: ${issueResults.filter((r) => r.action !== 'keep').length} issue actions, ${prResults.filter((r) => r.action !== 'keep').length} PR actions recommended`)

let applied = []
if (args && args.apply) {
  phase('Apply')
  // Only auto-execute the safe subset: high-confidence issue closes/comments and PR
  // stale-pings. Merging, closing, or rebasing PRs is always left to a human.
  const issueActions = issueResults.filter(
    (r) => r.confidence === 'high' && r.action !== 'keep'
  )
  const prPings = prResults.filter(
    (r) => r.confidence === 'high' && (r.action === 'stale-ping' || r.action === 'superseded') && r.comment
  )
  log(`applying ${issueActions.length} issue actions, ${prPings.length} PR comments`)
  applied = await parallel([
    ...issueActions.map((r) => () =>
      agent(
        `Execute this triage decision on ${inv.repo} issue #${r.number} (action: ${r.action}).
${r.action === 'comment'
  ? `Post this comment exactly: gh issue comment ${r.number} --repo ${inv.repo} --body <the comment below>. Do not close the issue.`
  : `Post the comment and close: gh issue close ${r.number} --repo ${inv.repo} --comment <the comment below>. Use --reason completed for close-fixed, --reason "not planned" for close-stale/close-duplicate.`}
Comment text:
---
${r.comment}
---
Report whether the command succeeded.`,
        { label: `apply-issue#${r.number}`, phase: 'Apply', schema: APPLY_SCHEMA }
      )
    ),
    ...prPings.map((r) => () =>
      agent(
        `Post this comment on ${inv.repo} PR #${r.number} via: gh pr comment ${r.number} --repo ${inv.repo} --body <the comment below>. Do NOT close or merge the PR.
Comment text:
---
${r.comment}
---
Report whether the command succeeded.`,
        { label: `apply-pr#${r.number}`, phase: 'Apply', schema: APPLY_SCHEMA }
      )
    ),
  ])
  applied = applied.filter(Boolean)
}

return {
  repo: inv.repo,
  dryRun: !(args && args.apply),
  issues: issueResults,
  prs: prResults,
  applied,
}
