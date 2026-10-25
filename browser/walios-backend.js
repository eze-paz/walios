// Single source of truth for the walios Python backend.
//
// Consumed by BOTH modules/sandpie-worker.js (run_python + the walios shell tool, via
// importScripts) and /walios/terminal.html (via a <script> tag), so the interactive
// terminal can never drift onto a different CPython than the one the agent runs. It had:
// python -> the old stdlib-only python.wasm, worker ?v=dlopen6, no certifi, no matplotlib.
//
// Plain classic script on purpose — sandpie-worker.js is a classic Worker and cannot
// `import`, so this assigns onto the global instead of exporting.

(function (g) {
  // Bumped with every wali-worker.js deploy.
  // dlopen9: the host no longer silently answers 0 for unimplemented `wali.*` imports.
  // __wasm_thread_spawn now returns EAGAIN so threading.Thread().start() raises
  // RuntimeError instead of trapping the whole interpreter (exit 139).
  // dlopen10: one armed itimer had TWO delivery sources (a polled deadline and a real
  // setTimeout) and neither cancelled the other, so a ONE-SHOT setitimer/alarm fired
  // SIGALRM twice -- measured 2 handler entries where 1 was expected. In Python the
  // second delivery re-entered the handler inside the except clause of the first and
  // went uncaught, which is exactly the _set_timeout pattern.
  // dlopen11: fork returns ENOSYS on a binary without Asyncify (CPython). It used to
  // hand back a pid and never run the child, so subprocess/os.popen waited out the
  // whole timeout; now they raise OSError immediately.
  // dlopen14: file modes persist. OPFS has no modes, so chmod lived in RAM and every
  // OPFS-backed file came back 0644 on the next boot (ssh refused its own key again).
  // opfs-worker.js now keeps a mode sidecar in IndexedDB (SETMODE op, returned with
  // READDIR); the kernel guesses 0600 under .ssh/ and 0755 for *.sh when there is no
  // record. Also: 'add-pkg' creates the /bin/<name> stub (a package added mid-session
  // was "not found" by name), and a seeded "#!" blob lands 0755.
  // dlopen15: the WASI shim re-syncs its memory views before every call. A guest that
  // grew linear memory (malloc -> memory.grow) detached the cached DataView, and the
  // next call touching it threw -> exit 139. QuickJS died on every real run (`-q`,
  // `-e`) because JS_NewRuntime grows once and then calls clock_time_get; `--version`
  // never grows. poll_oneoff also writes *nevents now instead of leaving it garbage.
  // dlopen16: every WASI process gets fd 3 = "/" preopened. Only the root module and
  // wasi-threads binaries had one, so a WASI child exec'd from the shell (qjs) could
  // not open any path: `qjs -e` worked, `qjs /tmp/t.js` and std.open() said ENOENT.
  // dlopen17: ONE engine. Every process runs on its own worker; the kernel is a
  // never-blocked async syscall server. The two older execution engines are gone, and
  // with them the stdin/mount SAB bridges that only
  // existed to feed a parked kernel, the sync lazy-fetch, and the separate wasi-threads
  // proxy (merged into the process worker: imported shared memory + thread mode). One
  // exec path (resolveExec + startProcess). WASI guests must link shared memory
  // (wasm32-wasi-threads); qjs/qjsc were rebuilt that way.
  // dlopen18: real pthreads. wali-musl's __wasm_thread_spawn starts a second instance of
  // the module on the same shared memory (threadSpawn), running its exported
  // __wasm_thread_start_libc; SYS_futex WAIT/WAKE block and wake for real in sysAsync;
  // gettid is per thread. python_cxx.wasm ?v=8 IMPORTS its memory (a thread cannot
  // share a memory the module defines) -- scripts/wasm-import-memory.mjs did that to the
  // deployed binary. threading.Thread, Lock, Event, Condition, Timer work in the REPL,
  // run_python and the walios() tool; a thread calling into a dlopen'd extension (numpy)
  // is still not supported (the side module is linked into the main instance's table).
  // dlopen19: the run message takes `links` (symlinks seeded before the guest runs);
  // runMessage adds /files -> /root so Pyodide-style paths work on this backend.
  // dlopen20: /dev/hostcall -- the guest->host RPC as a device, independent of stdio.
  // The frame-on-stdout / reply-on-stdin channel broke under any redirection: `python3
  // -c "import matplotlib" | head` sent the bundle request into the pipe and waited on a
  // stdin that was the shell's (a heredoc), and hung until the timeout. Requests written
  // to /dev/hostcall are answered on the same fd; `mount` is served by the kernel itself,
  // other ops reach the host as {t:'hostcall'} messages. sitecustomize, soffice and apk
  // use the device when present and fall back to stdio on an older kernel.
  // dlopen21: WASI fd_read/fd_write are the SAME code as the Linux read/write, per iov,
  // with errnos translated -- the second copy lacked the pty kind, so a WASI program's
  // output vanished in the terminal (pty stdio) while the walios() tool (plain stdio)
  // showed it. WASI fd_read also blocks now (waitReadable) instead of reading EOF.
  // dlopen22: an OPFS bridge that cannot start (no navigator.storage.getDirectory --
  // Playwright's WebKit on Windows) answers EIO instead of never answering, and the
  // kernel bounds its wait on the bridge to 20s and then declares the store dead. The
  // guest used to park forever on the first `ls /root`. Found by the browser test.
  // dlopen23: the OPFS bridge answers EBUSY (not EACCES) when another sync access handle
  // holds a file, and the kernel names that case. A run killed on timeout left its bridge
  // worker alive with its handles; the next run's fresh bridge could not open those files
  // and the kernel said "in the cloud but could not be downloaded" -- a git repo that had
  // just been cloned "became not a git repository". Hosts must terminate the bridge when
  // they kill a kernel (sandpie-worker does now).
  // dlopen24: clang as a GUEST. The kernel's page-side compiler bridge (cc/ar/wfetch/
  // wextract forwarded to the terminal page) is gone; yowasp's LLVM runs as an ordinary
  // WASI process (clang.wasm, shared memory). Needed for that: real per-file inodes in
  // stat (LLVM's FileManager keyed its cache on (dev, ino) and every file was ino 1, so a
  // header was "the same file" as the source that included it), path_symlink and
  // fd_filestat_set_size/set_times in the WASI shim, and import signatures for wasm
  // binaries exec'd from the VFS (a freshly compiled ./hello could not start).
  // sig26: kernel diagnostics under a pty are CRLF-framed (a bare newline left the cursor
  // mid-line and ls staircased after a walios: warning); an OPFS directory the cloud index
  // knows but has no children of lists empty instead of ENOENT.
  // sig27: the OPFS bridge stamps "picked up" into the control block, so the kernel's 20s
  // dead-bridge guard no longer fires on a legitimately slow operation -- opening a
  // cloud-only file downloads it from the cloud first, and one large file on a slow link
  // used to disable /root for the rest of the session. A slow op waits up to 10 min and
  // fails only itself.
  // sig28: /root is shareable. OPFS sync-access handles (exclusive per file, origin-wide)
  // are released 250ms after the last fd to the file closes instead of at the end of the
  // run/session; directory listings expire after 1.5s and reconcile (another kernel's new,
  // resized or deleted files show up); the bridge renames with FileSystemFileHandle.move()
  // (atomic, as git assumes) and stats a listing's entries in parallel. Several kernels --
  // terminal, tool, REPL, one per conversation -- work on the same repo at once.
  // sig29: the vfork child window belongs to the FORKING THREAD. git's sideband thread
  // exiting while the main thread spawned index-pack closed the window, and the execve
  // replaced the parent: "fatal: early EOF" on every deepening fetch of a shallow clone.
  // The WISP bridge answers EBADF/EOF for a stream the relay dropped instead of throwing
  // (which parked the kernel for good); git-upload-pack/receive-pack stubs for file://.
  const   // sig30: the child window's cwd/umask/signal table are the forking thread's view too (a
  // sibling thread saw the child's SIG_DFL table during the window); exit_group from any
  // thread ends the process; a thread may fork+exec.
// sig31: the 0-length pipe-write fix (POSIX says write(fd, buf, 0) transfers nothing;
  // the kernel pushed an empty chunk, the reader took it for EOF and exited, and the
  // writer's next real write got EPIPE), plus the walios-node hook that starts a JS
  // process worker for node-stub.wasm.
// mkdir32: mkdir in the workspace reported EPERM while SUCCEEDING -- opfsLoaded is a Map
// and the handler called .add(), which threw after the OPFS mkdir had already worked;
// the dispatcher turns any handler exception into -1. Broke `tar x` into /root,
// `mkdir ~/.ssh`, git clone into a new dir, and multi-call builds. mkdir(2) on an
// existing path is now EEXIST too, instead of silently succeeding (mkdir -p semantics).
// killall33: the tool's deadline stops the PROCESSES and keeps the kernel, so a run that
// runs out of budget no longer takes /tmp and every compiled module down with it.
// devexec36: posix_spawn landed in the kernel (ef751c3) without a bump, so any browser
// holding ?v=devexec35 kept running the kernel from BEFORE it -- node's child_process
// broken, and no way to tell from the page that it was serving a stale worker.
// devexec37: the SAME miss, with teeth. protectedDelete() -- the gate that stops a guest
// deleting /root/sandpie (the app's own conversations, memory, secrets, skills) -- shipped
// in d0fb1d5 WITHOUT a bump, so every browser kept the pre-guard kernel at ?v=devexec36.
// A day later a model ran `rm -rf sandpie && git clone ...` 8 times and the ungated cached
// worker let it through, costing one user ~100 conversations (and, via sync, on every
// device they owned). This bump carries that gate AND its WASI-ABI half (path_unlink_file /
// path_remove_directory / path_rename went straight to rmEntry with no check).
// A security gate is not deployed until this line moves.
// devexec40: opfs-worker.js mounts the home's ~/.ssh into folder-scoped kernels.
// devexec41: opfs-worker.js no longer plants hello-from-opfs.txt at the workspace root.
WORKER_V = 'inproc1';   // in-process JSPI engine: walios runs without cross-origin isolation

  // The main CPython. Reactor exec model: its exports are not wrapped in thunks that
  // re-run __wasm_call_ctors, which is what made every cross-module call re-initialise
  // mimalloc and flood stderr (25GB across a 12-package run, ~14x slower imports).
  const MAIN = 'python_cxx.wasm?v=8';
  const CLANG = 'clang.wasm?v=1';        // yowasp LLVM 22 core, shared+imported memory (see manifest())   // v=8: imports its memory (pthreads); same interpreter otherwise

  // Every package bundle, with the mount point it unpacks to.
  const BUNDLES = {
    stdlib:  ['pylib.tar.gz', '/py'],
    ext:     ['walios-ext.tar.gz', '/ext'],
    // certifi (TLS), packaging (micropip's resolver) and _shims/ctypes, which MUST be on
    // the path before stdlib ctypes or pandas fails to import. Also requests + urllib3 +
    // idna + charset_normalizer, and the two C extensions they need: zlib (which lived in
    // the 16MB numpy bundle) and _ssl (in the 11MB docs bundle). `import requests` used to
    // fail outright or drag a whole heavy bundle in for one HTTP call. Eager, ~2.4MB gz,
    // paid once per interpreter boot.
    extras:  ['walios-extras.tar.gz?v=4', '/site-packages'],
    numpy:   ['walios-numpy.tar.gz?v=3', '/site-packages'],
    docs:    ['walios-docs.tar.gz?v=5', '/site-packages'],
    mpl:     ['walios-mpl.tar.gz?v=3', '/site-packages'],
  };

  // Which bundle provides which top-level module, for mount-on-import-miss.
  const LAZY_PKGS = (() => {
    const m = {};
    for (const n of ['numpy', 'pandas', 'dateutil', 'pytz', 'tzdata', 'six', 'msgpack', 'simplejson']) m[n] = BUNDLES.numpy;
    for (const n of ['PIL', 'lxml', 'docx', 'openpyxl', 'pptx', 'reportlab', 'pypdf', 'PyPDF2', 'bs4', 'soupsieve',
                     'fontTools', 'xlsxwriter', 'olefile', 'OleFileIO_PL', 'striprtf', 'chardet', 'charset_normalizer',
                     'et_xmlfile', 'fpdf', 'pdfminer', 'typing_extensions']) m[n] = BUNDLES.docs;
    for (const n of ['matplotlib', 'mpl_toolkits', 'contourpy', 'kiwisolver']) m[n] = BUNDLES.mpl;
    return m;
  })();

  const PY_ENV = {
    PYTHONHOME: '/py',
    PYTHONPATH: '/site-packages/_shims:/py/Lib:/ext:/site-packages',
    PYTHONDONTWRITEBYTECODE: '1',
    MPLBACKEND: 'Agg',
    MPLCONFIGDIR: '/site-packages/_mplcache',      // prebuilt font cache: the in-guest scan costs >600s
    SSL_CERT_FILE: '/site-packages/certifi/cacert.pem',  // default context otherwise loads ZERO CA certs
  };

  g.WALIOS_BACKEND = {
    WORKER_V,
    MAIN,
    BUNDLES,
    LAZY_PKGS,
    PY_ENV,

    // Every program EVERY host has. python/python3 must resolve to the SAME binary
    // run_python uses (`pydl` is a historical alias). The rest used to be added per host:
    // the terminal had qjs/js/qjsc and rustc, the tool did not, so "qjs works in the
    // terminal but exits 127 in walios()" was a real report. One list now; a host adds
    // only what genuinely exists nowhere else (the terminal's page-side cc bridge).
    manifest(busybox) {
      return { busybox, sh: busybox, ash: busybox, hush: busybox,
               python: MAIN, python3: MAIN, pydl: MAIN,
               lua: 'lua.wasm',
               // QuickJS-ng 0.16.2, wasm32-wasi-threads. ?v=threads: the unversioned URL is
               // cached for a day, so a browser that had the OLD (private-memory) build kept
               // serving it after the rebuild -- the kernel refused it and qjs exited 127 in
               // one session while working in a fresh one.
               qjs: 'qjs.wasm?v=threads', js: 'qjs.wasm?v=threads', qjsc: 'qjsc.wasm?v=threads',
               // node: NOT a wasm guest. node-stub.wasm is a 652-byte WALI module that
               // declares the syscall imports and a shared env.memory, purely so the
               // kernel's _workerPlan() can derive names/sigs/memory the way it does for
               // any guest; wali-worker.js then starts walios-node-poc/node-proc-worker.js
               // instead of wali-proc-worker.js, and node's own lib/*.js runs on the page's
               // V8 over our syscalls. Absolute path because it does not live under
               // /walios/. See walios-node-poc/README.md.
               // node: the node-on-V8 host (walios-node-poc) is not part of this repo.
               ssh: 'ssh.wasm?v=ssl2', slogin: 'ssh.wasm?v=ssl2',
               make: 'make.wasm', gmake: 'make.wasm',
               // rustc: 'rustc-threads.wasm' -- 126MB, above GitHub's 100MB file cap; not in this build.
               // LLVM 22 (yowasp's build, converted to shared memory: scripts/wasm-import-memory.mjs
               // --shared) as an ordinary guest -- one 75MB module that dispatches on argv[0].
               // `cc`/`gcc` are the driver wrapper from walios/bin (the driver cannot spawn its
               // cc1/wasm-ld steps, the wrapper runs them as processes). It used to run on the
               // PAGE, terminal-only: `cc` in the tool hung to the timeout.
               // NB `ar`, `ranlib`, `ld`, `nm`, `strip` and `objdump` are deliberately NOT here:
               // they are seeded as absolutising wrapper scripts by toolBlobs() (see walios/bin/ar)
               // because clang.wasm resolves relative paths against "/". A manifest entry would
               // materialise /bin/ar and shadow the wrapper, since PATH is /bin:/usr/bin.
               // nm/strip/objdump WERE here, under their plain names, and that is exactly how
               // they stayed broken: `nm foo.o` looked for /foo.o. libtool builds its symbol
               // pipe from a relative-path nm probe, so the pipe came out empty and every
               // libtool link died with `eval: syntax error: unexpected "|"`. See walios/bin/nm.
               clang: CLANG, 'wasm-ld': CLANG, 'llvm-ar': CLANG, 'llvm-ranlib': CLANG,
               'llvm-nm': CLANG, 'llvm-strip': CLANG, 'llvm-objdump': CLANG };
    },

    // ONE mount strategy for every host. It used to fork: 'terminal' unpacked all six
    // bundles on the first `python` because an interactive shell had nothing to service
    // a lazy mount, while 'repl'/'tool' unpacked three. That fork is what let the walios()
    // tool ship with the lazy list and NO mount channel, so numpy/pandas/PIL/docx simply
    // did not exist there. Every host now carries hostChannel() below, so every host can
    // mount on demand and the mode argument is kept only so old callers keep working.
    eagerTars(_mode) {
      return { 'python.wasm': [BUNDLES.stdlib], [MAIN]: [BUNDLES.stdlib, BUNDLES.ext, BUNDLES.extras],
               'rustc-threads.wasm': [['wali-rust-sysroot.tar.gz', '/sysroot']],
               // clang's resource dir (builtin headers, compiler-rt) at /usr, the WALI musl
               // headers + libc at /sysroot. rustc's sysroot unions into /sysroot (lib/rustlib/).
               // onig-wali unpacks /opt/wali/{lib/libonig.a,include/oniguruma.h}, which `cc`
               // already has on its default -I/-L (see walios/bin/cc), so `-lonig` just works.
               // The OS ships it because WALI's ABI defeats oniguruma's own type selection:
               // st.h/regint.h pick a pointer-sized integer from {long, long long} only, and
               // here BOTH are 8 while a pointer is 4, so neither branch fires and st_data_t
               // and hash_data_type are never declared. Every dependent (jq's vendored copy
               // included) died on "unknown type name 'hash_data_type'". scripts/
               // build-oniguruma-wali.sh supplies uintptr_t by FLAG, with no source patch.
               [CLANG]: [['llvm-resources.tar.gz', '/usr'], ['wali-sysroot.tar.gz', '/sysroot'],
                         ['onig-wali.tar.gz', '/']] };
    },

    env(mode) {
      const e = Object.assign({}, PY_ENV);
      // NO_COLOR for the agent-facing hosts only. stdout looks like a tty here, so
      // colourising tools reach for ANSI: `jq '.a'` came back as
      // ESC[1;39m[ESC[0;39m2ESC[0m... which is noise in a tool result a model has to
      // read, and worse, noise it might quote back. The interactive TERMINAL is the one
      // host where colour is wanted, so it is excluded. NO_COLOR is the cross-tool
      // convention (jq, ls, grep, ripgrep and others honour it).
      if (mode !== 'terminal') e.NO_COLOR = '1';
      // This backend is the BROWSER host: every process gets its own worker and the
      // kernel answers blocking syscalls asynchronously (dlopen17), so epoll — and
      // therefore asyncio — works.
      // Hosts that cannot do this (the node one) simply never set the flag, and
      // walios-repl.py's _loop_usable() then drives coroutines directly.
      e.SANDPIE_ASYNCIO = '1';
      e.SANDPIE_LAZY_PKGS = JSON.stringify(LAZY_PKGS);
      // Autoconf reads $CONFIG_SITE before anything else and, failing that, only
      // $prefix/share/config.site -- where prefix is the PACKAGE's --prefix (default
      // /usr/local), not ours. So the file has to be named explicitly or configure would
      // never look at /etc. See toolBlobs() for what it contains and why.
      e.CONFIG_SITE = '/etc/config.site';
      return e;
    },

    // ---- TLS trust + git config, for EVERY walios host ------------------------
    // PY_ENV's SSL_CERT_FILE points at /site-packages/certifi/cacert.pem, which only
    // exists once python's companion tar has been mounted. Anything that needs TLS
    // before that -- `git clone`, wget, curl -- then has no trust store at all. The
    // terminal seeded a real bundle and pointed the env at it; the walios() TOOL did
    // not, so a clone that worked in the terminal died in the tool with
    //   SSL certificate problem: unable to get local issuer certificate
    // Both now take the same two helpers, so they cannot drift again.
    CA_PATH: '/etc/ssl/certs/ca-certificates.crt',

    tlsEnv() {
      return {
        SSL_CERT_FILE: this.CA_PATH,
        CURL_CA_BUNDLE: this.CA_PATH,
        GIT_CONFIG_GLOBAL: '/etc/gitconfig',
        // Never prompt. A private repo cloned without credentials made git ask
        // "Username for 'https://github.com':", read EOF on the tool's closed stdin,
        // and die with exit 128 and the error swallowed -- so the clone "silently
        // did nothing". With prompting off git fails immediately and SAYS it needs
        // credentials, which is the actionable message; put a token in the URL for a
        // private repo (https://x-access-token:TOKEN@github.com/owner/repo).
        GIT_TERMINAL_PROMPT: '0',
        // No pager and no interactive editor: an agent's `git log` must not try to run less,
        // and `rebase --continue` must not wait for an editor that cannot open.
        GIT_PAGER: 'cat', PAGER: 'cat', GIT_EDITOR: 'true', EDITOR: 'true',
      };
    },

    // ---- ONE boot for every host -----------------------------------------------
    // The run message a host posts to wali-worker.js, assembled in one place: the
    // busybox root, the package index folded into the manifest and lazyTars, the TLS
    // trust store + gitconfig, the apk client + its TSV, python's import-miss shim, and
    // the env every guest needs. Hosts add only what is theirs (the terminal's build
    // script, the tool's soffice bridge, the REPL's entry script). Every "worked in the
    // terminal, missing in the tool" bug in this file's history was a host forgetting one
    // of these; now there is nothing to forget.
    //
    //   kind        'terminal' | 'tool' | 'repl'  (selects env(kind) / eagerTars(kind))
    //   base        where /walios/ is reachable from the caller (default '/walios/')
    //   busybox     root module url (default this.BUSYBOX)
    //   pkgs        pkgIndex() result or a promise of one (optional)
    //   manifest    host additions; win over the package index
    //   lazyTars    host additions, keyed by module url
    //   blobs       host additions, path -> ArrayBuffer/Uint8Array; win over the defaults
    //   env         host additions; win over the defaults
    //   rpc         seed sitecustomize + SANDPIE_HOST_RPC=1 so python can ask for bundles
    //               over the frame channel (default true; the REPL brings its own)
    //   argv, cwd, pty, cols, rows   as in the run message
    // v=net5: linked against a libc whose long double code matches the compiler's 128-bit
    // layout (the old libc.a had frexpl/strtod built for the 80-bit layout: printf %f and
    // seq recursed to a stack overflow, awk floats and sort -n returned garbage). Also:
    // long options, ls colours (on a tty only), base64, md5sum/sha1sum/sha256sum, stat -c.
    // Built by sandpie-server/scripts/build-busybox-wali.sh. v=net4 was the fuller-coreutils build.
    // v=net6: same build plus --export=__stack_pointer/__tls_base, which the kernel needs to
    // hand an Asyncify fork child its parent's stack pointer (busybox `timeout` killed nothing
    // before: the grandchild's frames landed on top of the ones it inherited).
    // v=net7: tar (create/extract, -z/-j/-J via seamless gzip/bzip2/xz), gzip/gunzip/zcat,
    // bzip2/bunzip2, unzip, diff/cmp built in. The catalog's GNU tar was `rmt` and its
    // grep/diffutils/findutils were gnulib test helpers (the farm picked the wrong
    // executable); those catalog entries are gone and busybox provides the commands.
    BUSYBOX: 'busybox.wasm?v=net12',   // net8: CONFIG_FEATURE_WGET_OPENSSL -- `wget https://` works (helper: /bin/openssl)
    //                                net9:  FEATURE_TAR_OLDGNU/OLDSUN -- tar reads v7-format archives (jq's)
    //                                net10: ls -t / grep -A-B-C and the rest of the standard flag surface
    //                                net11: --import-memory -- the KERNEL owns the linear memory, so a
    //                                       terminated process no longer leaks it (see e2e-process-ceiling)
    //                                net12: CONFIG_DESKTOP -- the non-essential applet flags (od -A, ...)
    async runMessage(o) {
      const base = o.base || '/walios/';
      const bb = o.busybox || this.BUSYBOX;
      const pkgs = o.pkgs ? await o.pkgs : null;
      const rpc = o.rpc !== false;
      this._gitUser = o.gitUser || null;          // read by tlsBlobs() below
      const blobs = Object.assign({}, await this.tlsBlobs(base), await this.toolBlobs(base), pkgs ? this.pkgBlobs(pkgs) : {});
      if (rpc) {
        // On the default path for every python in the guest, so an import miss can ask
        // the host for the bundle. Without it numpy/pandas/PIL/docx simply did not exist
        // in the walios() tool while the terminal had them.
        try { const r = await fetch((o.base || '/walios/') + 'walios-sitecustomize.py?v=1'); if (r.ok) blobs['/site-packages/_shims/sitecustomize.py'] = await r.arrayBuffer(); } catch (_) {}
      }
      Object.assign(blobs, o.blobs || {});
      const env = Object.assign(
        { HOME: '/root', TERM: o.pty ? 'xterm' : 'dumb', PATH: '/bin:/usr/bin', PS1: o.pty ? 'walios:$PWD$ ' : '', HOSTNAME: 'walios', LC_ALL: 'C.UTF-8' },
        rpc ? { SANDPIE_HOST_RPC: '1' } : {},
        this.env(o.kind),
        // AFTER env(): its SSL_CERT_FILE points at certifi, which only exists once python's
        // companion tar is mounted, and git/wget need trust before that.
        this.tlsEnv(),
        o.env || {});
      return {
        t: 'run', wasm: bb,
        manifest: Object.assign({}, pkgs ? pkgs.manifest : {}, this.manifest(bb), o.manifest || {}),
        tars: [['rootfs.tar.gz', '/']], opfs: '/root', blobs,
        // /files is what the Pyodide backend calls the same OPFS root; a model that
        // learned "/files/..." paths there must not get ENOENT here.
        links: Object.assign({ '/files': '/root' }, o.links || {}),
        lazyTars: Object.assign({}, pkgs ? pkgs.lazyTars : {}, this.eagerTars(o.kind), o.lazyTars || {}),
        env, cwd: o.cwd || '/root', argv: o.argv, pty: !!o.pty, cols: o.cols || 120, rows: o.rows || 40,
      };
    },

    // The shell tools every host seeds into /usr/bin: the `cc` driver wrapper (also `gcc`),
    // wfetch/wextract (the fetch + unpack steps build-pkg uses; they were page requests
    // only the terminal answered) and build-pkg itself (an Alpine aport -> a wasm binary,
    // in-guest). Source of truth: sandpie-server/walios/bin/*, served under /walios/bin/.
    async toolBlobs(base) {
      const b = {};
      // npm-lite: installs a package from the real npm registry into /node_modules.
      // It is a #!/bin/node script, so it needs nothing but node -- and it used to be
      // seeded ONLY by walios-node-poc/index.html, which meant npm packages worked on
      // the poc page and were simply absent in the tool and the terminal.
      await Promise.all(['cc', 'wfetch', 'wextract', 'build-pkg', 'ar', 'ranlib', 'ld',
                         'nm', 'strip', 'objdump', 'pkg-config', 'npm-lite'].map(async (n) => {
        try { const r = await fetch((base || '/walios/') + 'bin/' + n + '?v=4'); if (r.ok) b['/usr/bin/' + n] = await r.arrayBuffer(); } catch (_) {}
      }));
      if (b['/usr/bin/cc']) b['/usr/bin/gcc'] = b['/usr/bin/cc'].slice(0);
      // config.site -- so a PLAIN `./configure` works, on every autotools package.
      //
      // config.guess does not recognise us. `uname -m` is wasm32 and `uname -s` is Linux,
      // and the config.guess shipped in current tarballs (jq 1.7.1 carries 2022-01-09) has
      // no wasm case at all -- zero matches for "wasm" in the whole script. So:
      //     ./configure
      //     configure: error: cannot guess build type; you must specify one
      // Every build here passed --build=... by hand, which is why this went unnoticed: it
      // is the FIRST thing a plain `./configure` does, so it blocked every autotools
      // package before a single check ran.
      //
      // config.site is autoconf's own hook for this, so no package is patched. Only `build`
      // is set: leaving `host` unset means host=build, i.e. NOT a cross build, so configure
      // keeps RUNNING its test programs (which works here) rather than guessing answers --
      // passing --host would silently switch it to cross mode and change every result.
      // The build_alias guard keeps an explicit --build=... winning: AC_CACHE_CHECK skips
      // its body when ac_cv_build is already set, so an unguarded preset would silently
      // override the caller.
      // config.sub already accepts the triple (`config.sub wasm32-unknown-linux-musl` echoes
      // it back); autoconf simply cannot DETECT it.
      //
      // Verified A/B on jq 1.7.1: without it `./configure` exits 1 on "cannot guess build
      // type"; with it, 193 checks, a Makefile, and -- because the build type is finally
      // known -- it also auto-detects the oniguruma we ship, with no --with-oniguruma flag:
      //     checking for oniguruma.h... yes
      //     checking for onig_version in -lonig... yes
      //
      // THE GUARD MUST BE AN `if`, NOT A `&&` LIST. autoconf SOURCES this file and treats a
      // non-zero return as fatal: `. "$ac_site_file" || as_fn_error ... "failed to load site
      // script"`. A trailing `test -z "$build_alias" && ac_cv_build=...` returns 1 whenever
      // build_alias IS set -- which is exactly what build-pkg does, it passes
      // --build=wasm32-unknown-linux-musl -- so the file that exists to make ./configure work
      // aborted every configure that named its build type:
      //     configure: error: failed to load site script /etc/config.site
      // Measured in-guest: `build_alias=x; . /etc/config.site` -> rc 1, unset -> rc 0. An `if`
      // returns 0 when its condition is false, so the guard survives and the file loads.
      b['/etc/config.site'] = new TextEncoder().encode(
        '# walios. config.guess has no wasm32 case, so tell autoconf what we are.\n' +
        '# Guarded so an explicit --build=... still wins (AC_CACHE_CHECK skips a set var).\n' +
        '# Only build is set: host then defaults to build, so this is NOT a cross build and\n' +
        '# configure keeps running its test programs.\n' +
        '# The guard is an `if`: autoconf aborts if sourcing this file returns non-zero, and\n' +
        '# a `&&` list returns 1 once build_alias is set.\n' +
        'if test -z "$build_alias"; then ac_cv_build=${ac_cv_build=wasm32-unknown-linux-musl}; fi\n'
      ).buffer;
      // sys/cdefs.h -- the reason is inside the file. musl omits it, and a glibc-written
      // package then fails at its FIRST header and mis-blames everything after it.
      // It goes in /sysroot/include, NOT /usr/include: cc runs -nostdlibinc with
      // -isystem /sysroot/include, so /usr/include is not on the include path and a
      // header placed there is present and invisible (measured -- the file existed and
      // the build failed with the identical error). bin/cc force-includes it, because
      // on glibc nothing includes sys/cdefs.h directly either: features.h pulls it in
      // from essentially every libc header, which is why packages just use the macros.
      b['/sysroot/include/sys/cdefs.h'] = new TextEncoder().encode([
        '/* sys/cdefs.h -- the glibc-isms musl leaves out, supplied by the OS.',
        ' *',
        ' * WHY: musl defines no __BEGIN_DECLS/__END_DECLS and ships no sys/cdefs.h at all, so a',
        ' * package written against glibc dies at its first header with',
        ' *     utf8.h:30:1: error: unknown type name |__BEGIN_DECLS|',
        ' * which names neither glibc nor the missing file. Worse, the parser desyncs after it and',
        ' * the REST of the log fills with "expected function body after function declarator" on',
        ' * perfectly good K&R definitions -- so the TAIL of the errors blames the wrong thing.',
        ' * That is what figlet looked like, and it cost two wrong diagnoses before someone read',
        ' * the FIRST error instead of the last.',
        ' *',
        ' * Measured, before this file existed:',
        ' *     make CC="cc -D__BEGIN_DECLS= -D__END_DECLS="',
        ' *       -> rc 0, 0 errors, a 175,488-byte figlet that runs.',
        ' *',
        ' * These wrap declarations for C++ linkage, so the definitions are the standard ones.',
        ' * NOT a package patch: the OS is supplying a header a Linux userland is expected to have.',
        ' */',
        '#ifndef _SYS_CDEFS_H',
        '#define _SYS_CDEFS_H',
        '',
        '#ifndef __BEGIN_DECLS',
        '# ifdef __cplusplus',
        '#  define __BEGIN_DECLS extern "C" {',
        '#  define __END_DECLS   }',
        '# else',
        '#  define __BEGIN_DECLS',
        '#  define __END_DECLS',
        '# endif',
        '#endif',
        '',
        '/* The two that travel with them in glibc headers: __P brackets a pre-ANSI prototype and',
        '   __THROW is a no-op outside glibc. The same packages use both. */',
        '#ifndef __P',
        '# define __P(args) args',
        '#endif',
        '#ifndef __THROW',
        '# define __THROW',
        '#endif',
        '',
        '#endif /* _SYS_CDEFS_H */',
        ''
      ].join(String.fromCharCode(10))).buffer;
      // Applet links. Real busybox is installed with `busybox --install -s`, one symlink per
      // applet in /bin and /usr/bin. We never did that, so /bin/sed and friends did not EXIST
      // as files. Running them was fine (resolveExecKey falls back to busybox by name), but
      // `test -f` / `test -x` said no -- and that is precisely how autoconf hunts for tools,
      // so configure died with "no acceptable sed could be found in $PATH" on a system whose
      // sed works perfectly. The content is irrelevant (it is not wasm, so exec still falls
      // through to busybox); only EXISTENCE is. busybox.links comes from the busybox build.
      try {
        const r = await fetch((base || '/walios/') + 'busybox.links');
        if (r.ok) { const marker = new TextEncoder().encode('#!busybox applet\n').buffer;
          for (const line of (await r.text()).split('\n')) { const q = line.trim();
            if (q.startsWith('/') && !b[q]) b[q] = marker.slice(0); } }
      } catch (_) { /* no links file: applets still RUN, they just cannot be stat'd */ }
      return b;
    },

    // Blobs to seed into the guest before it runs. `base` lets a caller on another
    // path reach /walios/ (the worker is not served from there).
    async tlsBlobs(base) {
      const b = {};
      const enc = (s2) => new TextEncoder().encode(s2).buffer;
      try {
        const r = await fetch((base || '/walios/') + 'cacert.pem');
        if (r.ok) b[this.CA_PATH] = await r.arrayBuffer();
      } catch (_) {}
      // safe.directory: the guest runs as root over an OPFS-backed tree, which git
      // otherwise refuses as "dubious ownership". Connection: close because the WISP
      // relay does not multiplex a kept-alive connection.
      // Read from the transcripts of an agent using git here: every `git log`/`diff` printed
      // "error: cannot run less" (there is no less), `git rebase`/`commit` without -c user.*
      // died with "unable to auto-detect email address (got 'root@wali.(none)')", and every
      // clone warned "templates not found in /home/aezequiel/share/git-core/templates" (the
      // build prefix). Each one cost the model a retry with a workaround flag. Defaults here;
      // a host may pass its own identity via runMessage({ gitUser: { name, email } }).
      const gu = (this._gitUser && this._gitUser.name) ? this._gitUser : { name: 'walios', email: 'walios@sandpie.invalid' };
      b['/etc/gitconfig'] = enc('[safe]\n\tdirectory = *\n[http]\n\tsslCAInfo = ' + this.CA_PATH
                                + '\n\textraHeader = Connection: close\n'
                                + '[core]\n\tpager = cat\n\teditor = true\n'
                                + '[user]\n\tname = ' + gu.name + '\n\temail = ' + gu.email + '\n'
                                + '[init]\n\tdefaultBranch = main\n\ttemplateDir = /usr/share/git-core/templates\n'
                                + '[advice]\n\tdetachedHead = false\n');
      b['/usr/share/git-core/templates/.keep'] = enc('');
      // git's file:// transport, and a fetch/push to a local path, run `sh -c "git-upload-pack
      // '<dir>'"`: the DASHED helpers must be in PATH. The build's libexec (git's exec-path)
      // is not shipped, so a local clone died with "git-upload-pack: not found". Stubs.
      b['/bin/git-upload-pack'] = enc('#!/bin/sh\nexec git upload-pack "$@"\n');
      b['/bin/git-receive-pack'] = enc('#!/bin/sh\nexec git receive-pack "$@"\n');
      b['/bin/git-upload-archive'] = enc('#!/bin/sh\nexec git upload-archive "$@"\n');
      return b;
    },

    // ---- Package index, for EVERY walios host --------------------------------
    // A runnable package can come from three places, all served under /walios/:
    //   pkgcache/index.json   binaries users compiled in-tab and uploaded (e.g. git)
    //   aports-catalog.json   the Alpine catalog; tier 'wasm' entries carry a wasm url,
    //                         the rest can only be BUILT (terminal.html's build button)
    // terminal.html folded all three into its boot manifest; the walios() tool folded
    // only pkgcache, so a package the UI could "add" did not exist for the model, and
    // neither host let the GUEST ask for one. One loader now, and `apk add` below asks
    // through the frame channel. Nothing is fetched until a binary is first exec'd.
    // `builtin` names (the host's own manifest) always win a name clash.
    async pkgIndex(base, builtin) {
      base = base || '/walios/';
      builtin = builtin || {};
      const get = async (u) => { try { const r = await fetch(base + u); return r.ok ? await r.json() : null; } catch (_) { return null; } };
      // Two sources: pkgcache/index.json (binaries users built) and aports-catalog.json (the
      // Alpine catalog). A third, a prebuilt repo `index.json`, was designed and never
      // deployed -- every boot 404'd on it -- so it is gone.
      const [cache, cat] = await Promise.all([get('pkgcache/index.json'), get('aports-catalog.json')]);
      const pk = {};                                         // name -> { url, tars, ver, kind, size, desc, src }
      const add = (name, e) => { if (!name || builtin[name] || pk[name]) return; pk[name] = e; };
      // pkgcache first: an in-tab build of X is the newest X (the ?t= is what
      // terminal.html does too -- pkgcache is served no-store but a wasm compile cache
      // keys on the URL).
      if (cache && Array.isArray(cache.packages)) for (const n of cache.packages) add(n, { url: 'pkgcache/' + n + '.wasm', kind: 'bin', src: 'pkgcache' });
      // Boot manifest = pkgcache, exactly what terminal.html puts on PATH at boot.
      // Catalog tier-'wasm' entries are NOT on PATH until asked for -- the UI's "add"
      // button and `apk add` both register them on demand -- so the two hosts agree on
      // what a fresh shell has, and `apk add` means the same thing in both.
      const manifest = {}, lazyTars = {};                    // lazyTars is keyed by module URL (see wali-worker ensureModule)
      for (const [n, e] of Object.entries(pk)) { manifest[n] = e.url; if (Array.isArray(e.tars) && e.tars.length) lazyTars[e.url] = e.tars; }
      const buildOnly = {};                                  // name -> desc; in the catalog, not built to wasm
      if (Array.isArray(cat)) for (const p of cat) {
        if (p.tier === 'wasm' && p.wasm) add(p.name, { url: p.wasm, desc: p.desc, kind: 'bin', src: 'catalog' });
        else if (p.name && !pk[p.name] && !builtin[p.name]) buildOnly[p.name] = p.desc || '';
      }
      // /etc/apk/packages.tsv -- name, version, kind, size, description, status. What
      // `apk search/list/info` read in the guest; only `apk add` needs the host.
      const clean = (s) => String(s == null ? '' : s).replace(/[\t\r\n]+/g, ' ').trim();
      const rows = [];
      for (const n of Object.keys(builtin).sort()) rows.push([n, '', 'builtin', '', '', 'installed'].join('\t'));
      // 'installed' = on PATH at boot (builtin, pkgcache); 'available' = catalog,
      // one `apk add` away.
      for (const n of Object.keys(pk).sort()) { const e = pk[n]; rows.push([n, clean(e.ver), clean(e.kind), clean(e.size), clean(e.desc), manifest[n] ? 'installed' : 'available'].join('\t')); }
      for (const n of Object.keys(buildOnly).sort()) rows.push([n, '', '', '', clean(buildOnly[n]), 'build-only'].join('\t'));
      return {
        pk, buildOnly, manifest, lazyTars,
        tsv: rows.join('\n') + '\n',
        resolve(name) { return pk[name] || null; },
      };
    },

    // Blobs every host seeds so the guest has a package client: the index above as a
    // TSV, and `apk` itself. Kept here so the tool and the terminal ship the same file.
    pkgBlobs(idx) {
      const enc = (s2) => new TextEncoder().encode(s2).buffer;
      const b = { '/usr/bin/apk': enc(this.apkScript()) };
      if (idx && idx.tsv) b['/etc/apk/packages.tsv'] = enc(idx.tsv);
      return b;
    },

    // The in-guest package client. Plain busybox sh: this busybox has no base64, so the
    // frame it sends is plain JSON and it asks (plain:1) for a plain-JSON reply -- see
    // hostChannel, which accepts both encodings. The reply is read from stdin: under the
    // headless tool stdin already hit EOF at boot and the host's line lands LATER, so an
    // empty read is retried (same rule sitecustomize.py follows), not treated as the end.
    apkScript() {
      return [
        '#!/bin/sh',
        '# apk -- walios package client. Packages are wasm binaries served by the host page.',
        '#   apk add <pkg>...    register with the running kernel (fetched on first exec)',
        '#   apk search [pat]    search name/description   apk list    apk info <pkg>',
        'TSV=/etc/apk/packages.tsv',
        'usage() { echo "usage: apk add <pkg>... | search [pattern] | list [installed|available|build-only] | info <pkg>" >&2; exit 2; }',
        '[ $# -ge 1 ] || usage',
        'cmd=$1; shift',
        'need_tsv() { [ -f "$TSV" ] || { echo "apk: no package index ($TSV missing)" >&2; exit 1; }; }',
        'show() { awk -F"\\t" \'{ st=$6; if (st=="installed") st="on PATH"; if (st=="available") st="apk add first"; if (st=="build-only") st="not built to wasm - try: build-pkg NAME";',
        '  printf "%-26s %-9s %s%s\\n", $1, $2, $5, "  [" st "]" }\' ; }',
        'case "$cmd" in',
        '  search) need_tsv; q=$(printf %s "$1" | tr A-Z a-z)',
        '    awk -F"\\t" -v q="$q" \'index(tolower($1), q) || index(tolower($5), q)\' "$TSV" | show ;;',
        '  list) need_tsv; f=${1:-}',
        '    awk -F"\\t" -v f="$f" \'f=="" || $6==f\' "$TSV" | show ;;',
        '  info) need_tsv; [ $# -ge 1 ] || usage',
        '    awk -F"\\t" -v n="$1" \'$1==n\' "$TSV" | show',
        '    awk -F"\\t" -v n="$1" \'$1==n{f=1} END{exit !f}\' "$TSV" || { echo "apk: unknown package $1" >&2; exit 1; } ;;',
        '  add) [ $# -ge 1 ] || usage',
        '    rc=0; k=0',
        '    for p in "$@"; do',
        '      case "$p" in *[!A-Za-z0-9._+-]*|"") echo "apk: bad package name: $p" >&2; rc=1; continue;; esac',
        '      # Always ask the host, even if /bin/<name> exists: the stub can outlive the',
        '      # manifest entry when a host reuses its worker for a new run. Registering',
        '      # twice is harmless.',
        '      if [ -f "$TSV" ] && awk -F"\\t" -v n="$p" \'$1==n && $3=="builtin"{f=1} END{exit !f}\' "$TSV"; then echo "$p: built-in"; continue; fi',
        '      k=$((k+1)); id="$$$k"',
        '      # /dev/hostcall (kernel RPC device) when present: the request then survives',
        '      # `apk add x | ...` or $(apk add x). Else the frame goes out on stdout as before.',
        '      if [ -e /dev/hostcall ] && exec 3<>/dev/hostcall; then via=dev; else via=stdio; fi',
        '      if [ $via = dev ]; then printf \'{"t":"call","id":%s,"op":"pkg","plain":1,"args":{"name":"%s"}}\\n\' "$id" "$p" >&3;',
        '      else printf \'\\002{"t":"call","id":%s,"op":"pkg","plain":1,"args":{"name":"%s"}}\\003\\n\' "$id" "$p"; fi',
        '      reply=""; n=0',
        '      while [ $n -lt 600 ]; do',
        '        if [ $via = dev ]; then IFS= read -r line <&3; ok=$?; else IFS= read -r line; ok=$?; fi',
        '        if [ $ok -eq 0 ]; then',
        '          case "$line" in *\'"t":"reply"\'*\'"id":\'"$id"[,\\}]*) reply=$line; break;; esac',
        '        else usleep 100000 2>/dev/null || sleep 1; fi',
        '        n=$((n+1))',
        '      done',
        '      [ $via = dev ] && exec 3>&-',
        '      case "$reply" in',
        '        "") echo "apk: no reply from the host for $p (is this shell running under a walios host?)" >&2; rc=1;;',
        '        *\'"ok_call":true\'*) echo "$p: added (fetched on first run)";;',
        '        *) err=$(printf %s "$reply" | sed -n \'s/.*"error":"\\([^"]*\\)".*/\\1/p\'); echo "apk: $p: ${err:-failed}" >&2; rc=1;;',
        '      esac',
        '    done',
        '    exit $rc ;;',
        '  *) usage ;;',
        'esac',
        '',
      ].join('\n');
    },

    // The guest->host frame channel, shared by the walios() tool and terminal.html so
    // there is one implementation to debug rather than two that drift.
    //
    // Frames ride fd 1 as \x02<base64 json>\x03. Under a pty that is also the user's
    // screen, which is workable in both directions but for one wrinkle measured here:
    // the pty ECHOES the reply we write to stdin straight back into the output, so the
    // base64 line lands on screen. We know the exact bytes we sent, so we drop the first
    // occurrence of each. Without that a terminal user sees a line of base64 every time
    // a package is mounted.
    //
    //   worker    the Worker running wali-worker.js
    //   onScreen  called with everything that is NOT a frame (write it to the terminal)
    //   onCall    optional, for ops other than 'mount'; returns a promise of the reply
    //   onMountMs optional, told how long a mount took so a caller can extend a deadline
    //   pkgs      optional pkgIndex() (or a promise of one); enables the 'pkg' op that
    //             `apk add` sends -- resolved here and registered with the kernel
    //
    // A frame is normally base64; a call carrying plain:1 is plain JSON and gets a plain
    // JSON reply (the shell client has no base64). Both are one line, so the echo strip
    // works the same way. Mounts are done by the kernel itself ('mount-tar'): it is never
    // blocked, so there is no host-side bridge any more.
    hostChannel({ worker, onScreen, onCall, onMountMs, pkgs }) {
      const STX = String.fromCharCode(2), ETX = String.fromCharCode(3);
      const enc = (str) => {
        const b = new TextEncoder().encode(str);
        let out = '';
        for (let i = 0; i < b.length; i += 0x8000) out += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
        return btoa(out);
      };
      const dec = (x) => new TextDecoder().decode(Uint8Array.from(atob(x), (c) => c.charCodeAt(0)));
      let pend = '';
      const echoes = [];                 // reply payloads we expect the pty to echo back
      const mounts = [];                 // in-flight mounts, awaiting 'tar-mounted'
      const reply = (f, o) => {
        // A request that came through /dev/hostcall (the kernel forwarded it as a
        // {t:'hostcall'} message) is answered the same way; the kernel puts the reply on
        // that fd. Nothing touches stdin and nothing is echoed to a pty.
        if (f.__kid !== undefined) { try { worker.postMessage({ t: 'hostcall-reply', id: f.__kid, reply: o }); } catch (_) {} return; }
        const body = JSON.stringify(Object.assign({ t: 'reply', id: f.id }, o));
        const payload = f.plain ? body : enc(body);
        echoes.push(payload);
        try { worker.postMessage({ t: 'stdin', data: payload + '\n' }); } catch (_) {}
      };
      // Strip our own echoed replies before anything reaches the screen.
      const emit = (text) => {
        if (!text) return;
        for (let i = 0; i < echoes.length; i++) {
          const at = text.indexOf(echoes[i]);
          if (at < 0) continue;
          let end = at + echoes[i].length;
          if (text[end] === '\r') end++;
          if (text[end] === '\n') end++;
          text = text.slice(0, at) + text.slice(end);
          echoes.splice(i, 1);
          i--;
        }
        if (text) onScreen(text);
      };
      const serve = (f) => {
        if (f.op === 'mount') {
          const a = f.args || {};
          if (!a.url) return reply(f, { ok_call: false, error: 'mount without url' });
          mounts.push({ url: a.url, f, t0: Date.now() });
          try { worker.postMessage({ t: 'mount-tar', url: a.url, prefix: a.prefix }); }
          catch (e) { reply(f, { ok_call: false, error: String((e && e.message) || e) }); }
          return;
        }
        if (f.op === 'pkg') {
          // `apk add <name>`: look the name up in the package index and register it with
          // the running kernel. The wasm is fetched on first exec, so this is instant.
          // Error strings deliberately carry no double quotes: the shell client pulls
          // them out of the JSON with a sed that stops at the first one.
          const a = f.args || {}, name = String(a.name || '').trim();
          if (!pkgs) return reply(f, { ok_call: false, error: 'this walios host has no package index' });
          if (!/^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(name)) return reply(f, { ok_call: false, error: 'bad package name' });
          Promise.resolve(pkgs).then((idx) => {
            const e = idx && idx.resolve(name);
            if (!e) {
              const bo = idx && idx.buildOnly && idx.buildOnly[name];
              return reply(f, { ok_call: false, error: bo !== undefined
                ? name + ' is in the Alpine catalog but not built to wasm yet. Try: build-pkg ' + name + ' (compiles it from Alpine source with the in-browser clang; slow, best effort)'
                : 'unknown package ' + name + ' (try: apk search ' + name + ')' });
            }
            try { worker.postMessage({ t: 'add-pkg', name, url: e.url, tars: Array.isArray(e.tars) && e.tars.length ? e.tars : undefined }); }
            catch (err) { return reply(f, { ok_call: false, error: String((err && err.message) || err) }); }
            reply(f, { ok_call: true, url: e.url, src: e.src || '' });
          }, (err) => reply(f, { ok_call: false, error: 'package index unavailable: ' + String((err && err.message) || err) }));
          return;
        }
        if (onCall) { Promise.resolve(onCall(f)).then((o) => reply(f, o)); return; }
        reply(f, { ok_call: false, error: 'unknown host op ' + f.op });
      };
      return {
        // Feed it fd-1 output. Returns nothing; screen text goes to onScreen.
        feed(strIn) {
          pend += strIn;
          for (;;) {
            const a = pend.indexOf(STX);
            if (a < 0) { emit(pend); pend = ''; return; }
            if (a > 0) emit(pend.slice(0, a));
            const b = pend.indexOf(ETX, a + 1);
            if (b < 0) { pend = pend.slice(a); return; }
            const raw = pend.slice(a + 1, b);
            pend = pend.slice(b + 1);
            if (pend.startsWith('\r')) pend = pend.slice(1);
            if (pend.startsWith('\n')) pend = pend.slice(1);
            let f = null;
            // base64 first (Python clients); a plain-JSON frame from the shell client
            // fails atob on its first '{' and is parsed as-is.
            try { f = JSON.parse(dec(raw)); }
            catch (_) { try { f = JSON.parse(raw); } catch (_2) { emit(STX + raw + ETX); continue; } }
            if (f && f.t === 'call') serve(f);
          }
        },
        // Call from the worker's onmessage for {t:'hostcall'}: a request the guest wrote to
        // /dev/hostcall. Served exactly like a stdout frame; the reply routes back by id.
        hostcall(m) {
          const f = (m && m.frame) || {};
          if (f.t !== 'call') return;
          f.__kid = m.id;
          serve(f);
        },
        // Call from the worker's onmessage for {t:'tar-mounted'}. True if it was ours.
        mounted(m) {
          const i = mounts.findIndex((x) => x.url === m.url);
          if (i < 0) return false;
          const wt = mounts.splice(i, 1)[0];
          if (onMountMs) onMountMs(Date.now() - wt.t0);
          reply(wt.f, m.ok ? { ok_call: true } : { ok_call: false, error: m.err || 'mount failed' });
          return true;
        },
        flush() { if (pend) { emit(pend); pend = ''; } },
      };
    },
  };
})(typeof self !== 'undefined' ? self : globalThis);
