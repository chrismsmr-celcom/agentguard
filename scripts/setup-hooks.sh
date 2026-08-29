#!/usr/bin/env bash
# scripts/setup-hooks.sh
#
# Installs development hooks for AgentGuard.
# Run ONCE after git clone:
#   bash scripts/setup-hooks.sh

set -e

echo "🛠️  Setting up AgentGuard development environment..."

# 1. Install pre-commit
if ! command -v pre-commit &> /dev/null; then
    echo "📦 Installing pre-commit..."
    pip install pre-commit
fi

# 2. Install pre-commit hooks (uses .pre-commit-config.yaml)
echo "🔗 Installing pre-commit hooks..."
pre-commit install

# 3. Install pre-push hook (COPIES scripts/hooks/pre-push → .git/hooks/)
echo "🔒 Installing pre-push hook..."
cp scripts/hooks/pre-push .git/hooks/pre-push
chmod +x .git/hooks/pre-push

# 4. Run initial validation
echo "🧪 Running initial validation..."
pre-commit run --all-files || true

echo ""
echo "✅ Setup complete! Hooks installed:"
echo "   - pre-commit: runs on every git commit"
echo "   - pre-push: runs before git push"
echo ""
echo "📖 See README.md 'Development Setup' for details."
