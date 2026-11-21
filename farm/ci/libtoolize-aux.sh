#!/bin/sh
# libtoolize, then its auxiliary files where configure.ac wants them (farm-wave.yml installs this
# as /usr/local/bin/libtoolize, the real one as libtoolize.real).
#
# libtoolize 2.6.2 reads configure.ac with its own m4 trace (extract-trace), and on the runners
# that trace can come back empty: it then says "Remember to add 'LT_INIT'", puts the aux files
# in '.' and leaves the tarball's own (older) ltmain.sh in AC_CONFIG_AUX_DIR -- configure then
# runs a libtool whose ltmain.sh does not match its LT_INIT ("This is libtool 2.5.4, but the
# definition of this LT_INIT comes from libtool 2.6.2": gnutls, libnl3), or finds no aux files
# at all ("cannot find required auxiliary files": gpm). On that message, when configure.ac does
# use libtool, the files go into its AC_CONFIG_AUX_DIR as libtoolize would have put them.
real=/usr/local/bin/libtoolize.real
aux_src=/usr/local/share/libtool/build-aux
out=$("$real" "$@" 2>&1); rc=$?
[ -n "$out" ] && printf '%s\n' "$out"
[ $rc = 0 ] || exit $rc
for a in "$@"; do case "$a" in -n|--dry-run|--dry*) exit 0;; esac; done
# A project that keeps its own aclocal.m4 and runs autoconf without aclocal (openldap: libtoolize
# --force, then autoconf) gets the new ltmain.sh but keeps the old LT_INIT in aclocal.m4 ("This is
# libtool 2.6.2, but the definition of this LT_INIT comes from libtool 2.4.6"). libtoolize says
# what to do: "You should add the contents of the following files to 'aclocal.m4'" -- appended,
# the later definitions win (and an aclocal run afterwards rewrites the file anyway).
case "$out" in *"to 'aclocal.m4'"*)
  # (also when aclocal wrote it: openldap's is aclocal's, but its recipe never reruns aclocal)
  if [ -f aclocal.m4 ]; then
    printf '%s\n' "$out" | sed -n "s/^[^ ]*:[[:space:]]*'\(\/[^']*\.m4\)'\$/\1/p" | while read -r m; do
      [ -f "$m" ] && { printf '\n# farm libtoolize: from %s\n' "$m"; cat "$m"; } >> aclocal.m4 && echo "farm libtoolize: aclocal.m4 += $m"
    done
  fi;;
esac
case "$out" in *"Remember to add 'LT_INIT'"*) ;; *) exit 0;; esac
ca=configure.ac; [ -f "$ca" ] || ca=configure.in; [ -f "$ca" ] || exit 0
grep -qE '^[[:space:]]*(LT_INIT|AC_PROG_LIBTOOL|AM_PROG_LIBTOOL)\b' "$ca" || exit 0
aux=$(sed -n 's/^[[:space:]]*AC_CONFIG_AUX_DIR([[]*\([^])]*\)[]]*).*/\1/p' "$ca" | head -n 1)
[ -n "$aux" ] || aux=.
mkdir -p "$aux" || exit 0
for f in ltmain.sh config.guess config.sub install-sh; do
  [ -f "$aux_src/$f" ] || continue
  # ltmain.sh always (it must match the LT_INIT aclocal just took from 2.6.2); the others only
  # when missing (a recipe may carry a newer config.sub).
  if [ "$f" = ltmain.sh ] || [ ! -e "$aux/$f" ]; then
    rm -f "$aux/$f"; cp "$aux_src/$f" "$aux/$f" && echo "farm libtoolize: $aux/$f from libtool (configure.ac uses LT_INIT)"
  fi
done
exit 0
