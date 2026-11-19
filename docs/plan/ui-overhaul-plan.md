# UI overhaul plan (WP9b)

**Repo:** `~/Documents/canary`. Frontend paths are relative to `canary/`. This plan sits next to `multiturn-build-plan.md` and extends WP9; it does not replace it.

## 0. Baseline (2026-11-19)

The WP9 branch is `multiturn-wp9` at 4de82b8. It forked from the old `multiturn`, before WP3, WP7, WP10 and WP11 were merged.

- **Already built (the functional D8 list):**
  - target onboarding wizard with test-connection
  - campaign builder with production safe defaults (`lib/safeDefaults.ts`)
  - SSE client with `Last-Event-ID` resume (`lib/sse.ts`) and live-state reducer (`lib/liveState.ts`)
  - live conversation grid and transcript (`components/LiveParts.tsx`, `Transcript.tsx`)
  - results and findings triage
  - proxy forwards the user session, with no server token and `VITE_API_TOKEN` removed
- **Checks:** `npm ci && npm run build && npm run lint && npx vitest run` all pass. The JS bundle is 297 kB (91 kB gzip). 13 unit tests.
- **Gaps:**
  - It calls `/api/v2/*` routes that WP8 has not built yet.
  - There are no Playwright tests.
  - The visual shell is still the original marketing site: `Hero` and `Console`, everything in JetBrains Mono, fade-slide animations.
  - There is no design system, no loading, empty or error states, no accessibility pass, and no mobile layout.

## 1. Scope

**Default decision (the user may override):** the overhaul is a visual and UX redesign of the operator console on top of WP9's working features. It does not rewrite the data layer.

**In scope:**
1. **Design system.** Tailwind theme tokens for color, type scale, spacing, radii and elevation, defined as CSS variables, with light and dark themes and a theme toggle. Body text uses a proportional UI font. Mono is kept for evidence, transcripts and IDs only.
2. **App shell.**
   - Replace the marketing `Hero` and `Console` landing with an authenticated console: left nav for Targets, Campaigns, Findings, Reports and Admin, and a top bar with org, user and role.
   - A global kill-switch status pill, visible to everyone; only admins can toggle it.
   - The marketing landing moves to `/about`, or is dropped.
3. **Shared components.** Each lives in `components/ui/`, has typed props and no data fetching:
   - Table with paging, the total count and sorting
   - Badge: severity, status, ASI code
   - Meter: budget and rate
   - Drawer, Dialog and Toast
   - EmptyState, ErrorState and Skeleton
   - CodeBlock with redaction markers styled
   - CI bar for success-rate confidence intervals
4. **Pages, redesigned.** Each page gets real loading, empty and error states.
   - **Targets.** A list that shows verification status. The wizard becomes a stepper with these steps: endpoint → auth → session mode → template and response path → test connection → verify.
   - **Campaign builder.**
     - Techniques are picked from a grouped list.
     - Trials, turns and budgets each show a live cost estimate.
     - Production targets lock the safe defaults (rps≤1, parallel≤2, total≤300). The UI explains why the controls are locked.
   - **Live view.**
     - A grid of technique × trial cells with status colors.
     - Clicking a cell opens a transcript drawer: turn by turn, monitor hits highlighted, the critical-stop reason shown.
     - A budget meter (requests and USD), a Cancel button, and an SSE connection indicator.
   - **Results.** A per-technique success-rate table with CI bars, and a gate comparison against a baseline campaign that reuses WP10's `GateResult` shape.
   - **Findings triage.**
     - Paged with a total count, plus a lifecycle board: new, confirmed, false-positive, fixed.
     - Each finding deep-links to the exact turn that failed. The reviewer is recorded.
   - **Reports.** JSON, Markdown and PDF downloads from `/api/v2/reports/{id}`.
5. **Accessibility.** WCAG 2.2 AA contrast in both themes. Every flow works with the keyboard alone. Focus rings are visible. Status is never shown by color alone: an icon or text always goes with it. `prefers-reduced-motion` is respected.
6. **Mobile.** The read-only views (live grid, transcript, findings) work at 375 px. The builder and the wizard can be desktop-first.
7. **Tests.**
   - Vitest for the components and reducers.
   - A Playwright smoke test that runs a fake campaign end to end: log in, onboard `fake_target`, launch, watch the grid, open a transcript, cancel, triage a finding.
   - An axe-core check runs on each page.

**Out of scope:** new backend features, and changes to `lib/sse.ts` or `lib/liveState.ts` semantics. Bug fixes in those files are allowed.

## 2. Security rules (non-negotiable; enforced in review and CI)

- **No secrets in the bundle.** No token in any `VITE_*` variable. CI greps the built bundle using `.github/bundle-secret-patterns.txt` (WP10).
- **Redacted by default.** Transcripts and evidence are shown redacted. The "show raw" control appears only for the `evidence:read_raw` permission, every raw view calls the audited endpoint, and the UI states that the view is logged.
- **Kill switch.** Only `admin` sees the toggle. Everyone sees its status.
- **Operator gates.** Only `operator` can launch, and only against verified targets in their own org. Unverified targets cannot be selected in the builder.
- **Production safe defaults are enforced in the UI.** The backend still enforces them too (WP3 `normalize_request` and the WP7 refusal path). The UI is never the only guard.
- **No `dangerouslySetInnerHTML` on target output.** Transcripts render as text, and Markdown reports render through a sanitizer.
- **Third-party loads.** No third-party scripts. Fonts are self-hosted.

## 3. Sequencing

| Step | Work | Depends on | Agent |
|---|---|---|---|
| 1 | WP8 API v2 and auth: pin the route and role contract, and generate `lib/v2.ts` types from the OpenAPI schema | WP7 merged | builder + Opus review |
| 2 | Rebase or merge WP9 onto the current `multiturn`, align it to WP8's real routes, add Playwright on `fake_target` | WP8 | builder + review |
| 3a | Design tokens, `components/ui/`, app shell | none (can use a mock API built from `contracts.ts`) | builder |
| 3b | Page redesigns, one commit per page, plus accessibility and mobile | 2, 3a | builder + review |
| 4 | Playwright and axe on CI, bundle grep, then merge into `multiturn` | 3b | review |

There is a cap of 2 concurrent agents. Step 3a may run alongside step 1 when a slot is free, against a mock API.

## 4. Done when

- `npm run build`, `lint` and `vitest` pass.
- Playwright smoke and axe pass against `fake_target` on the real stack.
- The bundle grep is clean.
- A reviewer has approved the security rules in section 2.
- Screenshots of every page in both themes, and at 375 px for the read-only views, are attached to the review.
