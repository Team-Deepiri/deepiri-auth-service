# Git Hooks Directory

This directory contains Git hooks that protect the `main` and `dev` branches.

## Setup

Run the setup script to configure Git to use these hooks:

```bash
./setup-hooks.sh
```

Or manually:

```bash
git config core.hooksPath .git-hooks
chmod +x .git-hooks/pre-push
```

## Hooks

- **pre-push**: Blocks direct pushes to `main` and `dev` branches

## Testing

Try pushing to main or dev - you should see an error:
```bash
git checkout main
git push origin main
# ❌ ERROR: You cannot push directly to 'main'.
```

