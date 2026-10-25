"""Lazy package mounting for EVERY python in walios, not just the warm REPL.

The heavy packages (numpy, pandas, Pillow, python-docx, matplotlib, reportlab, …)
live in tarballs the host mounts on demand. Until now only ONE of the three walios
hosts could actually get at them:

  run_python (warm REPL)  walios-repl.py installs its own meta_path finder that calls
                          out to the host on an import miss                    -> works
  terminal.html           no host RPC channel, so it unpacks EVERY bundle up front
                          before the prompt appears                            -> works, slowly
  walios() shell tool     lazy bundle list (nothing heavy unpacked) AND no way to ask
                          for a mount                                          -> BROKE

Measured before this file existed, same script in both: `import numpy` PASSED in the
terminal and raised ModuleNotFoundError in the walios() tool; same for pandas, PIL and
docx. Four of seven capability checks diverged.

This puts the finder on the default path (site imports `sitecustomize` at startup), so
a plain `python3 -c "import numpy"` gets the same packages the REPL does, wherever it
runs. The framing is the same one soffice.py already uses: a base64 JSON frame on fd 1,
the reply as a base64 JSON line on fd 0.

It is INERT unless the host says it is listening (SANDPIE_HOST_RPC=1). The terminal
does not set it — there the bundles are already mounted, nothing would answer a frame,
and emitting one into a pty would just corrupt the user's screen.
"""

import os
import sys


def _install():
    if os.environ.get("SANDPIE_HOST_RPC") != "1":
        return                                  # no host is listening for frames
    raw = os.environ.get("SANDPIE_LAZY_PKGS")
    if not raw:
        return

    import base64
    import json
    import time

    try:
        lazy = json.loads(raw)
    except Exception:
        return
    if not lazy:
        return

    seq = [0]

    # /dev/hostcall is the kernel's RPC channel that does not ride stdio. On the old
    # channel (frame on fd 1, reply on fd 0) `python3 -c "import matplotlib" | head`
    # sent the bundle request INTO THE PIPE and waited for a reply that went to the
    # shell -- a hang until the timeout. Fall back to stdio only on a kernel without it.
    _dev = [None]
    try:
        _dev[0] = os.open("/dev/hostcall", os.O_RDWR)
    except OSError:
        pass

    def _send(obj):
        os.write(1 if _dev[0] is None else _dev[0], b"\x02" + base64.b64encode(json.dumps(obj).encode("utf-8")) + b"\x03\n")

    def _read_reply(cid, timeout=600.0):
        """Same reader as soffice.py: an empty read is EOF-already-seen, not the end of
        the conversation — the host's chunk lands later, so sleep and read again."""
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = os.read(0 if _dev[0] is None else _dev[0], 65536)
            except OSError:
                chunk = b""
            if chunk:
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        m = json.loads(base64.b64decode(line))
                    except Exception:
                        continue
                    if m.get("t") == "reply" and m.get("id") == cid:
                        return m
                continue
            time.sleep(0.05)
        return {"ok_call": False, "error": "no reply from the host within %ds" % int(timeout)}

    def _hostcall(op, **args):
        seq[0] += 1
        cid = seq[0]
        _send({"t": "call", "id": cid, "op": op, "args": args})
        return _read_reply(cid)

    class _MountOnMiss:
        """Last-resort meta_path finder: normal resolution runs first, and this only
        acts once everything else has failed to find `fullname`."""

        def __init__(self):
            self._tried = set()
            self._mounted = set()

        @staticmethod
        def _resolve(fullname):
            import importlib

            importlib.invalidate_caches()
            try:
                return importlib.util.find_spec(fullname)
            except Exception:
                return None

        def find_spec(self, fullname, path=None, target=None):
            top = fullname.split(".")[0]
            bundle = lazy.get(top)
            if not bundle or top in self._tried:
                return None
            self._tried.add(top)     # set BEFORE retrying: find_spec re-enters meta_path
            url = bundle[0]
            # Keyed on the BUNDLE, not the module: openpyxl and et_xmlfile share one
            # tarball, and keying on the module re-downloaded it per package.
            if url in self._mounted:
                return self._resolve(fullname)
            r = _hostcall("mount", url=url, prefix=bundle[1])
            if not r.get("ok_call"):
                return None
            self._mounted.add(url)
            return self._resolve(fullname)

    import importlib.util  # noqa: F401  (find_spec lives here)

    sys.meta_path.append(_MountOnMiss())


try:
    _install()
except Exception:
    pass          # never let this break interpreter startup
