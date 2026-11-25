#!/usr/bin/env bash
# Audit the Python dependencies declared in the current repo.
#
# Handles all three shapes used across these repos: requirements*.txt,
# uv.lock (exported with uv), and pyproject.toml-only projects.
# Called by CI (.github/workflows/security.yml) and the pre-commit hook.
#
# Requires: uv (https://docs.astral.sh/uv/)
set -euo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

# PYSEC-2026-2447: diskcache uses pickle and has no fixed release yet. The
# service only reads a cache directory it owns, so the risk is accepted until
# upstream ships a fix. Remove this once diskcache > 5.6.3 is available.
ignores=(--ignore-vuln PYSEC-2026-2447)
audited=0

if [[ -f uv.lock ]]; then
	reqs="$(mktemp)"
	trap 'rm -f "$reqs"' EXIT
	uv export --frozen --no-dev --no-hashes -q | grep -v '^-e ' >"$reqs"
	uvx --from pip-audit pip-audit -r "$reqs" "${ignores[@]}"
	audited=1
fi

while IFS= read -r -d '' req; do
	if grep -qE '^(-e |.*\.\./)' "$req"; then
		echo "security-audit: skipping $req (local path/editable reference)"
		continue
	fi
	echo "security-audit: $req"
	uvx --from pip-audit pip-audit -r "$req" "${ignores[@]}"
	audited=1
done < <(find . -type f -name 'requirements*.txt' \
	-not -path './.venv/*' -not -path '*/node_modules/*' \
	-not -path '*/build/*' -not -path '*/dist/*' -print0)

if [[ "$audited" -eq 0 && -f pyproject.toml ]]; then
	uvx --from pip-audit pip-audit . "${ignores[@]}"
fi
