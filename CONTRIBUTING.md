# Contributing

```bash
npm ci
cp .env.example .env.local   # SERV_API_KEY optional: without it the deterministic planner runs
npm run dev
npm run check                # lint + typecheck + tests + eval (what CI runs, minus build)
```

- **Verdicts stay deterministic.** New detectors go in `src/lib/engine/` and return evidence. Never let model output set or change a verdict, score or quote.
- **Every detector gets a unit test** in `tests/detectors.test.ts`, with a positive and a negative example. If it changes a fixture verdict, update `src/lib/fixtures.ts` and the eval.
- **No network in tests.** Use `offlineNet` or a mocked `Net`, and the scripted SERV mocks in `tests/helpers/mocks.ts`. Live checks are opt-in (`LIVE=1`).
- **Never say "safe".** User-facing text says "No warning signs found".
- Keep commits small and describe the user-visible change. CI must be green before merging to `main` (Vercel deploys `main`).
