# ADR 0022: Command-first terminal presentation

Date: 2026-10-18. Status: development implementation; local source checks,
hosted CI and installed acceptance retain separate scopes.

## Context

Starting a menu from bare `localpin` surprises users who expect a command
overview. Long unwrapped setup paragraphs, repeated status fields and styling
inside individual workflows obscure the current action. Improving appearance
must retain the authentication, recovery and private-input contracts in
[ADR 0019](0019-guided-setup-orchestration.md),
[ADR 0020](0020-setup-accounting-maintenance.md) and
[ADR 0021](0021-flexible-credentials.md).

## Decision

Both `localpin` and its `localpinctl` compatibility name use the same behavior:

- No arguments print concise help and return success, without a terminal,
  account lookup or broker connection. `--help`/`-h` shows full help.
- `menu` explicitly opens the existing inline numbered menu. `setup` explicitly
  starts or resumes onboarding. Existing command spellings remain available.
- `help COMMAND` and `COMMAND --help`/`-h` describe one command; integration
  subcommands have focused help. `--version`/`-V` prints the version.
- Global `--color auto|always|never`, including `--color=VALUE`, controls human
  output. Auto follows the actual destination and honors `NO_COLOR`,
  `TERM=dumb` and redirection. Explicit color selection overrides auto policy.
  JSON and completion source never receive decoration.
- Global `--no-input` rejects menu, setup, enrollment, change, disable,
  migration and recovery before terminal access, account inspection or broker
  contact. It supplies no defaults, secret source or confirmation bypass.
  Read-only status/doctor, help, version, completions and integration guidance
  remain available.
- `completions bash|zsh|fish` prints static completion source. The RPM installs
  the same scripts in standard shell directories, for both executable names,
  and installs `localpin(1)` with a `localpinctl(1)` alias. Scripts complete
  public commands, flags and closed backend/color/shell choices only; no
  subprocess performs account, broker or credential queries.

Keep output in normal terminal scrollback. A shared dependency-free semantic
renderer owns headings, status rows, paragraphs, stage labels, warnings and next
actions. Use a restrained terminal palette, readable spacing and wrapping at the
available width with a conservative fallback. Do not require custom fonts,
emoji, a pager, an alternate screen or a prompt framework. State remains
explicit in words as well as color.

Setup shows the current stage, short explanation and next action. Detailed
component information stays in `doctor` and command help. Preparation summarizes
the changes and offers the complete sanitized policy diff on request; viewing
or skipping the diff always leads to a separate apply confirmation. Pausing at
the review choice applies nothing. Keep software-protection
tradeoffs, session termination, actual unlock/password tests, recovery rehearsal
and operator attestations beside the actions they authorize. A shorter screen
cannot reduce the prerequisites or imply that an attestation independently
proves a test. Installation, enrollment, trial and activation remain distinct.

Results use stdout; failures use stderr. Interactive guidance and private prompts
continue on the protected controlling terminal. Output rendering reports write
failures; a broken output pipe exits quietly with status 0. Other exit statuses
are 0 success, 1 operational failure, 2 invalid arguments and 130 cancellation.

## Boundaries

Retain the closed command grammar and fixed diagnostics that never repeat
rejected argument values. Do not accept secrets through argv, environment,
stdin, completion helpers or configuration. Global color settings do not create
a LocalPIN-specific secret environment channel. Preserve schema-version-2
status/doctor JSON and all existing authorization and protocol behavior.

Keep the hardened terminal reader, foreground ownership checks, bounded input,
deadlines, process dump protection, masking, zeroizing secret storage, signal
handling and restoration. Sanitize external worker/account text before trusted
presentation adds styling; accepting escape sequences from worker messages is
not a color implementation. Presentation capabilities follow the actual output
destination rather than assuming stdout describes `/dev/tty`.

## Validation and consequences

Exercise synthetic command/help/error cases, output streams, widths, color
policy, JSON purity, no-input refusal before contact, completion scripts and
existing PTY cancellation/restoration/job-control tests. Packaging checks cover
manual/completion installation and completion syntax where shell tools are
available. No live account, everyday PAM configuration or physical TPM attempts
are needed for these source checks.

Local source results and unavailable tools must be recorded honestly in the PR;
hosted CI and installed Fedora KDE results are separate evidence. Prior M8 and
flexible-credential reports retain their tested builds. Independent M9 review,
physical hardware validation and final signed-release gates remain open.
