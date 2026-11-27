# Whole packages (index kind `pkg`)

A farm package normally reaches `apk` as ONE program (`<pkg>.wasm`, named by its smoke test):
openssh was only `scp`. A directory here makes build-one.sh also publish everything the package
installs as `<pkg>.pkg.tar.gz`, index kind `pkg` with a `bins` list; `apk add` mounts it at `/`.

- `exclude`  tar --exclude patterns, one per line (`#` comments): files walios cannot use.
  Headers, static libraries, pkg-config files, docs and info pages are always left out.
- `root/`    files copied over the install before packing (walios glue, e.g. a wrapper).

Programs (wasm files) are packed 0755. The `exe` smoke test still gates the package.
