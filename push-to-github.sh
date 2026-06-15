#!/usr/bin/env bash
# Run once from Terminal to publish VelocityCertify as an independent GitHub package.
# Requires: gh CLI authenticated (brew install gh && gh auth login)
#
# STEP 0 (one-time, ~30 seconds in browser):
#   Create the velocitycertify org at https://github.com/organizations/new
#   Then run: bash push-to-github.sh
set -euo pipefail

ORG="velocitycertify"
REPO_NAME="velocitycertify-swift"
REPO="$ORG/$REPO_NAME"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLEANUP_REPO="ttmschmidt/skyfire-systems"   # accidental repo — will be deleted

# ── 0. Preflight ──────────────────────────────────────────────────────────────

echo ""
echo "── [0/5] Preflight"

if ! command -v gh &>/dev/null; then
  echo "ERROR: gh CLI not found. Install: brew install gh && gh auth login"; exit 1
fi

GH_USER=$(gh api /user --jq '.login' 2>/dev/null || echo "")
if [[ -z "$GH_USER" ]]; then
  echo "ERROR: gh not authenticated. Run: gh auth login"; exit 1
fi
echo "    Authenticated as: $GH_USER"

# Verify the org exists — must be created manually at github.com/organizations/new
if ! gh api /orgs/$ORG &>/dev/null; then
  echo ""
  echo "  ✗ The '$ORG' GitHub org does not exist yet."
  echo ""
  echo "  Create it now (30 seconds):"
  echo "    https://github.com/organizations/new"
  echo "    Organization name: $ORG   |   Plan: Free"
  echo ""
  echo "  Then re-run: bash push-to-github.sh"
  exit 1
fi
echo "    Org $ORG: ✓"

# ── 1. Delete accidental repo ─────────────────────────────────────────────────

echo ""
echo "── [1/5] Cleaning up $CLEANUP_REPO"
if gh api /repos/$CLEANUP_REPO &>/dev/null; then
  if gh api /repos/$CLEANUP_REPO -X DELETE 2>/dev/null; then
    echo "    Deleted ✓"
  else
    echo "    Skipped (needs delete_repo scope — run: gh auth refresh -h github.com -s delete_repo)"
  fi
else
  echo "    Already gone ✓"
fi

# ── 2. Create velocitycertify-swift under the org ────────────────────────────

echo ""
echo "── [2/5] Creating $REPO"
# Use /orgs/:org/repos — NOT 'gh repo create' (which hits /users/:org and 404s for orgs)
RESP=$(gh api /orgs/$ORG/repos \
  --method POST \
  -f name="$REPO_NAME" \
  -f description="Independent trust layer for Mac Silicon game certification" \
  -f homepage="https://velocitycertify.com" \
  -F has_wiki=false \
  -F private=false \
  2>&1 || true)

if echo "$RESP" | grep -q '"already exists"'; then
  echo "    Repo already exists — will push to it ✓"
elif echo "$RESP" | grep -q '"full_name"'; then
  echo "    Created ✓"
else
  echo "    Response: $RESP"
fi

# ── 3. Init local git repo ────────────────────────────────────────────────────

echo ""
echo "── [3/5] Git init in $DIR"
cd "$DIR"

if [[ ! -d .git ]]; then
  git init
fi

git add .

if git diff --cached --quiet; then
  echo "    Nothing new to commit"
else
  git commit -m "Initial release: VelocityCertify 1.0.0

Independent Swift Package for Mac Silicon game certification.
Tested on its own CI — not inside any consuming app.

- CertificationService: live manifest lookup + Ed25519 verification
- ManifestCache: TTL-cached, network-injectable for tests
- Full test suite: network, security, integration, performance
- Ed25519 public key bundled as the trust anchor"
fi

# ── 4. Push main ──────────────────────────────────────────────────────────────

echo ""
echo "── [4/5] Push main"
REMOTE_URL="https://github.com/$REPO.git"
if git remote get-url origin &>/dev/null; then
  git remote set-url origin "$REMOTE_URL"
else
  git remote add origin "$REMOTE_URL"
fi
git branch -M main
git push -u origin main
echo "    Pushed ✓"

# ── 5. Tag v1.0.0 ─────────────────────────────────────────────────────────────

echo ""
echo "── [5/5] Tag v1.0.0"
git tag -l | grep -q "^v1.0.0$" || git tag -a v1.0.0 -m "VelocityCertify 1.0.0"
git push origin v1.0.0 2>/dev/null || git push --tags origin
echo "    Tagged ✓"

# ── Done ─────────────────────────────────────────────────────────────────────

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  VelocityCertify is live                                      ║"
echo "║  https://github.com/velocitycertify/velocitycertify-swift    ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Next: pull it into Velocity"
echo "  cd /Users/theo/Developer/SKYFIRE/SkyFire/Velocity/Velocity"
echo "  swift package resolve"
echo ""
