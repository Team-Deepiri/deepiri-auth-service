# CodeQL Setup for deepiri-auth-service

This folder contains the CodeQL configuration for security scanning in this service.

## What each file does

- `.github/workflows/codeql.yml`
  - Defines when scans run and how GitHub Actions executes CodeQL.
- `.github/codeql/codeql-config.yml`
  - Defines what folders to include and ignore during analysis.

## CodeQL workflow breakdown (`.github/workflows/codeql.yml`)

### `name: CodeQL`
The display name in the Actions tab.

### `on.pull_request.branches` and `on.push.branches`
```yaml
on:
  pull_request:
    branches: [main, dev]
  push:
    branches: [main, dev]
```
Runs scans when PRs target `main` or `dev`, and when commits are pushed to `main` or `dev`.

### `permissions`
```yaml
permissions:
  actions: read
  contents: read
  security-events: write
```
Uses least-privilege permissions. `security-events: write` is required so CodeQL can upload findings.

### Language setup (current)
```yaml
with:
  languages: javascript-typescript
```
This workflow currently runs analysis for JavaScript and TypeScript.

### Checkout step
```yaml
with:
  fetch-depth: 0
```
- `fetch-depth: 0` keeps full git history (safe default for analysis and troubleshooting).

### Initialize CodeQL
```yaml
uses: github/codeql-action/init@v3
with:
  config-file: ./.github/codeql/codeql-config.yml
```
Starts the CodeQL engine and loads `.github/codeql/codeql-config.yml`.

### Analyze
```yaml
uses: github/codeql-action/analyze@v3
```
Executes queries and uploads results to GitHub Security.

## Config breakdown (`.github/codeql/codeql-config.yml`)

### `paths`
The current include list is intentionally scoped to auth runtime and script code:

```yaml
paths:
  - src
  - scripts
```

### `paths-ignore`
Generated/build/runtime artifact paths are excluded to reduce noise and runtime:

```yaml
paths-ignore:
  - '**/node_modules/**'
  - '**/dist/**'
  - '**/build/**'
  - '**/coverage/**'
  - '**/logs/**'
  - '**/*.min.js'
```

## Best practices

1. Keep trigger scope intentional.
   Use branch filters (`main`, `dev`) to control cost and noise.
2. Keep language list explicit.
   Only include languages with meaningful source code.
3. Keep `paths` focused when used.
   Include actively maintained production code first.
4. Exclude generated/vendor artifacts.
   Keep dependencies, build outputs, logs, and minified files in `paths-ignore`.
5. Pin to stable major action versions.
   `@v3` is the current stable major for CodeQL actions.
6. Review alerts regularly.
   Triage high/critical findings first and suppress only with documented reasoning.

## Maintenance examples
Keeping this updated as code and language coverage evolve is important. Here are common maintenance changes.

### Keep language scope aligned with this service
This workflow currently analyzes JavaScript/TypeScript only:

```yaml
with:
  languages: javascript-typescript
```

Only change this value when this service adds production code in another supported language.

### Include only specific top-level packages
Add explicit `paths` only for directories that exist in this checkout.

Example:

```yaml
paths:
  - src
  - scripts
```

### Exclude another generated folder
Add a glob to `paths-ignore`, for example:

```yaml
- '**/generated/**'
```
