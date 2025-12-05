#!/bin/sh
# Install Git hooks into .git/hooks so they run automatically

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT" || exit 1

echo "🔧 Installing Git hooks for deepiri-auth-service..."

mkdir -p .git/hooks

if [ -f ".git-hooks/post-checkout" ]; then
    cp .git-hooks/post-checkout .git/hooks/post-checkout
    chmod +x .git/hooks/post-checkout
    echo "✔ Installed post-checkout hook"
fi

if [ -f ".git-hooks/post-merge" ]; then
    cp .git-hooks/post-merge .git/hooks/post-merge
    chmod +x .git/hooks/post-merge
    echo "✔ Installed post-merge hook"
fi

git config core.hooksPath .git-hooks

echo "✅ Git hooks installed and configured!"

