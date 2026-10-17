# Repository guidance

## Branches and pull requests

- Use a dedicated, short-lived branch for every focused change, including
  documentation, configuration, and follow-up fixes for a new task. Start new
  work from the latest `main`; continue on an existing branch only when updating
  that same unmerged change or responding to its review.
- Never make development commits on `main` or push changes directly to `main`.
  Use descriptive names such as `docs/project-overview`, `fix/frame-limit`, or
  `feat/account-diagnostics`.
- Commit and push the completed change, then create a pull request targeting
  `main` with a clear problem statement, resulting behavior, and actual
  validation results. Leave it open for the maintainer to review. Do not merge
  a PR without explicit maintainer instruction.
- Preserve unrelated working-tree changes and published history. Stage explicit
  paths, inspect the diff, and keep each PR focused. Do not change the Git
  identity or delete other branches as part of routine work.

## Project context

- Read [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution and validation
  workflow. The [product specification](docs/product-specification.md), current
  [implementation plan](docs/implementation-plan.md), and relevant ADRs define
  authentication and recovery contracts.
- Keep current behavior, historical evidence, and outstanding release gates
  distinct. LocalPIN is experimental; M8.1 installed evidence does not complete
  M9 independent review or physical hardware validation.
- Never use the everyday machine's PAM setup, real credential state, or physical
  TPM failure budget as a test fixture. Use synthetic inputs and isolated,
  disposable environments. Never commit secrets or unsanitized authentication
  logs. Follow [SECURITY.md](SECURITY.md) for suspected vulnerabilities.

## Validation and documentation

- Run checks appropriate to the changed behavior and report results honestly.
  For documentation-only changes, check links, examples against the source,
  and whitespace; a full Rust or installed-VM suite is unnecessary unless the
  change also affects executable behavior.
- For code, native policy, or packaging changes, use the relevant checks and
  isolated evidence described in CONTRIBUTING.md. Record unavailable checks
  and environment limitations. Local results and hosted CI results are separate.
- Keep the README concise and link detailed contracts, reports, and runbooks.
  Do not weaken security/recovery requirements or claim unperformed validation.
