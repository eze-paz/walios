# Build farm on GitHub Actions

Cross-compiles Alpine aports to `wasm32-wali` on free GitHub runners, and publishes the
results as a release. Each run plans and builds once and publishes once.

- **Run it:** Actions → **farm** → Run workflow.
- **Inputs:**
  - `pkgs`: a list of packages to build.
  - `sample`: a random N from `catalog.txt`, used when `pkgs` is empty.
  - `all`: build the whole catalog.
  - `chunk`: packages per job.

## Pieces

- **`toolchain.sh`:** sets up the toolchain from upstream LLVM 22.1.3 release binaries plus
  `wali-sysroot.tar.gz` from release `pkgs-2026-10-31`. These are the same compiler and libc
  that walios's own CPython is built with. `wali-cc`/`wali-c++` add every flag a walios
  guest needs. CI caches the result.
- **`plan.js`:** works out the package set and its build order.
  - **Dependencies:** each package's dependency closure comes from its APKBUILD
    (`depends` + `makedepends`, minus build tools).
  - **Waves:** packages are grouped into up to 4 dependency waves.
  - **Chunks:** each wave is split into chunks of `CHUNK` packages per matrix job. A
    wave stays at or under 256 jobs, and at most 20 run at once.
- **`build-one.sh`:** builds one aport the same way the old `farm/build-one.sh` did.
  - **Build:** it runs the recipe's own `prepare`/`build`/`package` with the WALI toolchain
    injected, plus the gnulib no-signals overlay.
  - **Smoke test:** the main executable must run `--version` on `host/host.js` without
    trapping.
  - **Outputs:** a result row, the `.wasm`, and an `.overlay.tar.gz` of what it installed.
- **`make-index.js`:** writes the published package index, `index.json`. For each package
  it records version, kind, file, size and sha256, plus the failures and their reasons.

## Waves and libraries

A library built in wave N reaches waves after N as an artifact. Its `usr/` overlay is
unpacked into each later job's `-I`/`-L` path. Cycles are broken, and chains deeper than
4 are folded into the last wave, so a few late packages may miss a dependency and fail.
Rerun those with `pkgs`.

## Consuming it

Each release is a frozen snapshot, tagged `farm-YYYY-MM-DD-<run>`. The walios package CDN
serves the files at `https://walios-pkgs.gasn2-04a.workers.dev/<tag>/<file>`, with CORS
enabled. `index.json` maps each package name to its file.
