# Repository working instructions

- Communicate with the owner in Russian. Write source, identifiers, commit
  messages, repository documentation and PR descriptions in English.
- Read `docs/PROGRESS.md`, `docs/NEXT_TASK.md`, `docs/DECISIONS.md`,
  `docs/KNOWN_LIMITATIONS.md` and the relevant `docs/spec` chapters before work.
- Implement bounded tasks following specification phases P00–P18. Keep actual
  results separate from plans, unavailable platform tests and independent review.
- The owner authorizes automatic push and merge for this development work.
  Run relevant checks, commit reviewable changes, push and merge completed work
  without asking again. Respect branch protection and preserve unrelated work;
  never force-push or bypass a failing required check.
- An empty repository can be bootstrapped directly on `main`. Use normal PRs
  for later changes when GitHub API access is available. If API access is
  unavailable and branch policy permits, a checked fast-forward to `main` is
  acceptable. Do not claim GitHub CI passed without its run evidence.
- GitHub Actions may validate/build the project. Push/merge authorization does
  not authorize production deployment, live-data deletion, or destructive
  production migrations.
- Use the existing checkout: cloud tasks are already isolated. Do not create a
  Git worktree unless the owner explicitly asks.
- Preserve `docs/spec` as the supplied source baseline. Record contradictions,
  changes and their rationale in decisions rather than silently editing it.
- No server plaintext fallback, invented cryptography, real secrets in fixtures,
  verification bypass, or fabricated physical-device/audit results.
- Update progress, decisions, limitations, test evidence and the exact next task
  with each completed slice. Keep experiments separate from production code.
