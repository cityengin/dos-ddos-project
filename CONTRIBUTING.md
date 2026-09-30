# Contributing & Workflow

This document defines the commit convention and the day-to-day workflow for this repository.

## Commit convention — Conventional Commits

Every commit message follows [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary in the imperative mood>
```

- Keep the summary under ~72 characters and in English.
- `scope` is optional but recommended. Suggested scopes for this project:
  `attacks`, `detector`, `experiments`, `analysis`, `lab`, `docs`, `repo`.

### Types

| Type       | Use for                                                        |
|------------|----------------------------------------------------------------|
| `feat`     | A new feature or capability                                    |
| `fix`      | A bug fix                                                       |
| `docs`     | Documentation only (README, CHANGELOG, this file, the report)  |
| `refactor` | Code change that neither fixes a bug nor adds a feature        |
| `perf`     | A performance improvement                                      |
| `test`     | Adding or fixing tests / experiments                           |
| `chore`    | Tooling, config, housekeeping (`.gitignore`, deps, etc.)       |
| `build`    | Build system or Docker image changes                           |

### Examples (specific to this project)

```
feat(detector): add inbound-only counting via --victim flag
fix(detector): stop counting victim SYN-ACK replies as a second source
feat(experiments): add narrated one-command demo with Docker preflight
feat(attacks): support IP spoofing in syn_flood with --spoof
docs(readme): document detection mechanism and limitations
refactor(analysis): extract episode detection into a helper
chore(repo): add .gitignore for Python and Docker artifacts
build(lab): install procps in attacker image for pkill
```

## Development workflow

Keep it to four steps per change:

1. **Edit** the code or docs.
2. **Update `CHANGELOG.md`** — add a bullet under the `## [Unreleased]` section
   (create it if missing) using the Keep a Changelog groups: `Added`, `Changed`, `Fixed`,
   `Removed`.
3. **Commit** with a Conventional Commit message (see above). Stage related changes together:

   ```bash
   git add -A
   git commit -m "fix(detector): correct SYN flood tag threshold"
   ```

4. **Push**:

   ```bash
   git push
   ```

## Cutting a release

When a set of changes is ready to be tagged:

1. Move the `## [Unreleased]` bullets into a new `## [x.y.z] - YYYY-MM-DD` section.
2. Bump the version following [Semantic Versioning](https://semver.org/):
   `MAJOR` for breaking changes, `MINOR` for new features, `PATCH` for fixes.
3. Commit and tag:

   ```bash
   git add CHANGELOG.md
   git commit -m "docs(changelog): release vX.Y.Z"
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push --follow-tags
   ```

## Reminder

All repository content (code comments, docs, commit messages) is written in **English**.
This is an educational project — never target anything outside the isolated lab.
