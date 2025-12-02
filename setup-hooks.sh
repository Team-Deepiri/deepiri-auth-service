#!/bin/sh
# Setup script for Git hooks

echo "🔧 Setting up Git hooks for deepiri-auth-service..."

# Install hooks into .git/hooks for automatic setup
if [ -f "scripts/install-git-hooks.sh" ]; then
    chmod +x scripts/install-git-hooks.sh
    ./scripts/install-git-hooks.sh
else
    # Fallback: just configure hooksPath
    git config core.hooksPath .git-hooks
    if [ -f .git-hooks/pre-push ]; then
        chmod +x .git-hooks/pre-push
        echo "✔ Git hooks enabled. You are now protected from pushing to 'main' or 'dev'."
    else
        echo "⚠️  Warning: .git-hooks/pre-push not found. Make sure you're in the repository root."
        exit 1
    fi
fi

