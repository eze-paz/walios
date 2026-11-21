#!/bin/bash
# fetch-artifacts.sh <run-id>  (GH_TOKEN set): a farm run's res-* artifacts into ./res and its
# aliases artifact into ., one at a time with backoff. actions/download-artifact fetching ~430
# artifacts of another run at once trips GitHub's secondary rate limit (farm-publish, R78).
set -uo pipefail
RUN=${1:?usage: fetch-artifacts.sh <run-id>}
mkdir -p res
get() {  # get <url> <out>
  for t in $(seq 1 30); do
    gh api "$1" > "$2" 2>/dev/null && [ -s "$2" ] && return 0
    echo "fetch-artifacts: retry $t for $1"; sleep $(( t < 6 ? 20 * t : 120 ))
  done; return 1
}
list=""
for t in $(seq 1 30); do
  list=$(gh api --paginate "repos/{owner}/{repo}/actions/runs/$RUN/artifacts?per_page=100" -q '.artifacts[] | select(.expired | not) | "\(.id) \(.name)"') && break
  sleep 60
done
[ -n "$list" ] || { echo "fetch-artifacts: no artifacts for run $RUN" >&2; exit 1; }
n=0
while read -r id name; do
  case "$name" in res-*) dest=res;; aliases) dest=.;; *) continue;; esac
  get "repos/{owner}/{repo}/actions/artifacts/$id/zip" a.zip || { echo "fetch-artifacts: $name failed" >&2; exit 1; }
  unzip -qo a.zip -d "$dest" && rm -f a.zip; n=$((n + 1)); sleep 1
done <<<"$list"
echo "fetch-artifacts: $n artifacts from run $RUN"
