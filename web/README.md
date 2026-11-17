# PhishForge Console (web)

Minimal React + TypeScript + Vite + Tailwind operator dashboard for the
PhishForge API (M8-lite). It talks to the existing Go API — there is no
frontend login backend; you paste an operator API key (minted by
`devtools/seed`) on first load and it is kept in `localStorage` and sent as the
`X-API-Key` header on every request.

## Prerequisites

- Node.js 20+ (developed on Node 24)
- The PhishForge API running on `http://localhost:8080` (see repo root)

## Commands

The project uses npm scripts (no Makefile — this repo does not use `make` on
Windows). `pnpm` works too; swap `npm run` for `pnpm`.

| Task                 | npm                 | pnpm              |
| -------------------- | ------------------- | ----------------- |
| Install deps         | `npm install`       | `pnpm install`    |
| Dev server (:5173)   | `npm run dev`       | `pnpm dev`        |
| Type-check only      | `npm run typecheck` | `pnpm typecheck`  |
| Production build     | `npm run build`     | `pnpm build`      |
| Preview the build    | `npm run preview`   | `pnpm preview`    |

`npm run build` runs `tsc --noEmit` (type-check) then `vite build`; it fails on
any type error.

## Dev proxy (no CORS)

`vite.config.ts` proxies `/api/v1` to `http://localhost:8080`, so the browser
makes same-origin requests and the API needs no CORS handling. Point it
elsewhere with an env var:

```bash
VITE_API_TARGET=http://127.0.0.1:9090 npm run dev
```

## Getting a key

From the repo root, mint a tenant + user + API key:

```bash
go run ./devtools/seed -tenant "Acme" -email you@acme.test -role admin
```

Paste the printed `pf_<keyID>.<secret>` token into the console's key screen.
The console probes your role (admin can list tenants, operator can list
campaigns) to show/hide admin-only actions; it does not transmit the role.

## Views

Campaigns (list/create/detail: launch, links, send, per-recipient state),
Contacts & Groups (+ CSV import), Templates (create/edit), Sending Profiles
(write-only password), Approvals (admin approve/reject), Activity (audit +
events), and Tenants (admin).

## Notes

- The send button surfaces the API's 403 approval-gate error inline; a template
  must be approved before the API accepts a send.
- This is a first-cut UI (M8-lite): no automated frontend tests yet, and polling
  is manual (Refresh buttons) rather than live.
