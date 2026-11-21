#!/bin/bash
# publish.sh <tag>  (cwd: res/ from the waves, index.json, summary.md, logs.tar.gz; GH_TOKEN set)
#
# Uploads a farm run as release <tag> (+ <tag>-b past the ~1000-file limit). Resumable: a
# release that exists is reused and only the assets it lacks go up, so a publish cut short can
# run again (farm-publish.yml). A full run is ~1100 uploads, past GITHUB_TOKEN's 1000 requests
# an hour (R78: "API rate limit exceeded for installation"), so on a refusal it waits for the
# limit's reset instead of giving up after a few 30 s retries.
set -uo pipefail
TAG=${1:?usage: publish.sh <tag>}
wait_limit() {
  local reset now
  reset=$(gh api rate_limit -q '.resources.core.reset' 2>/dev/null || echo 0)
  now=$(date +%s)
  if [ "${reset:-0}" -gt "$now" ] && [ "$(gh api rate_limit -q '.resources.core.remaining' 2>/dev/null || echo 0)" -lt 50 ]; then
    echo "publish: rate limited, waiting $(( reset - now + 15 ))s"; sleep $(( reset - now + 15 ))
  else sleep 90; fi   # a secondary (abuse) limit: no reset time, a pause clears it
}
ensure() {  # ensure <release> <create args...>
  local r=$1; shift
  for t in $(seq 1 20); do
    gh release view "$r" >/dev/null 2>&1 && return 0
    gh release create "$r" "$@" && return 0
    wait_limit
  done; return 1
}
have() {  # the release's uploaded assets, all pages (a release object alone may list only some)
  local id; id=$(gh api "repos/{owner}/{repo}/releases/tags/$1" -q .id 2>/dev/null) || return 1
  gh api --paginate "repos/{owner}/{repo}/releases/$id/assets?per_page=100" -q '.[] | select(.state == "uploaded") | .name' 2>/dev/null
}
upload() {  # upload <release> <files...>: only the missing ones, 10 at a time
  local r=$1; shift
  local tries=0
  while :; do
    local got missing=()
    got=$(have "$r") || { wait_limit; continue; }
    for f in "$@"; do grep -qxF "$(basename "$f")" <<<"$got" || missing+=("$f"); done
    [ ${#missing[@]} = 0 ] && { echo "publish: $r complete ($# files)"; return 0; }
    tries=$((tries + 1)); [ $tries -gt 40 ] && { echo "publish: $r still lacks ${#missing[@]} files" >&2; return 1; }
    echo "publish: $r: ${#missing[@]} to upload"
    local i
    for ((i = 0; i < ${#missing[@]}; i += 10)); do
      gh release upload "$r" --clobber "${missing[@]:i:10}" || { wait_limit; break; }
      sleep 2
    done
  done
}
ensure "$TAG" --title "walios farm $TAG" --notes-file summary.md --prerelease || exit 1
mkdir -p spill; while read -r f; do [ -n "$f" ] && [ -f "res/$f" ] && mv "res/$f" spill/; done < res/spill.txt
# runnable packages (.wasm) and pure-Perl/Lua modules (.mod.tar.gz)
pk=$(ls res/*.wasm res/*.mod.tar.gz 2>/dev/null || true)
[ -n "$pk" ] && { upload "$TAG" $pk || exit 1; }
sp=$(ls spill/* 2>/dev/null || true)
if [ -n "$sp" ]; then
  ensure "$TAG-b" --title "walios farm $TAG (b)" --notes "Packages of $TAG past the first release's file limit; see $TAG/index.json." --prerelease || exit 1
  upload "$TAG-b" $sp || exit 1
fi
# the overlays in parts under GitHub's 2 GiB asset limit (R78's one tarball, 2.1 GB+, was refused
# with "422 Validation Failed"): overlays.tar.gz, overlays-2.tar.gz, ... (farm-e2e.yml fetches all)
ov=(); part=1; sum=0; list=()
pack() {
  [ ${#list[@]} = 0 ] && return
  local n; n=$([ $part = 1 ] && echo overlays.tar.gz || echo "overlays-$part.tar.gz")
  tar czf "$n" -C res "${list[@]}" && ov+=("$n"); part=$((part + 1)); sum=0; list=()
}
for f in $(cd res && ls *.overlay.tar.gz 2>/dev/null); do
  sz=$(stat -c %s "res/$f")
  [ $((sum + sz)) -gt 1800000000 ] && pack
  list+=("$f"); sum=$((sum + sz))
done; pack
# the index last: its presence means the release is whole
upload "$TAG" logs.tar.gz "${ov[@]}" || exit 1
upload "$TAG" index.json
