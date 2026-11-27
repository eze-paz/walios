# Raw X11 client (no libX11) that logs the input it receives: the display test's witness that
# keys and clicks injected from the page (XTEST, modules/walios-x11.js) reach an X client.
# Opens a 200x150 window at +360+260 selecting KeyPress/ButtonPress and appends one line per
# event to argv[1]:  __KEY <keycode> <state>  /  __BTN <button> <x> <y>.  Button 3 = done:
# it writes __KEYDONE and keeps the window up (so the screen does not change under the test).
import socket, struct, sys, time

out = open(sys.argv[1] if len(sys.argv) > 1 else '/tmp/keys.log', 'a')
def log(s): out.write(s + '\n'); out.flush()
t0 = time.time(); s = None
while time.time() - t0 < 60:
    try: s = socket.create_connection(('127.0.0.1', 6000), timeout=None); break
    except OSError: time.sleep(0.5)
if s is None: log('__KEYPROBE no server'); sys.exit(1)
def recvn(n):
    b = b''
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c: raise EOFError
        b += c
    return b
s.sendall(struct.pack('<BxHHHHxx', ord('l'), 11, 0, 0, 0))
head = recvn(8); body = recvn(struct.unpack('<H', head[6:8])[0] * 4)
rid_base = struct.unpack('<I', body[4:8])[0]; vlen = struct.unpack('<H', body[16:18])[0]; nformats = body[21]
off = 32 + ((vlen + 3) & ~3) + 8 * nformats
root = struct.unpack('<I', body[off:off + 4])[0]
win = rid_base + 1
# CreateWindow: CWBackPixel (0x2) | CWEventMask (0x800); event mask KeyPress|ButtonPress|Exposure
s.sendall(struct.pack('<BBHIIhhHHHHII', 1, 0, 10, win, root, 360, 260, 200, 150, 0, 1, 0, 0x802) + struct.pack('<II', 0x3366cc, 0x8005))
# WM_NORMAL_HINTS (atom 40, type WM_SIZE_HINTS 41): USPosition|USSize|PPosition|PSize, so a
# window manager keeps it where the test clicks
hints = struct.pack('<18I', 1 | 2 | 4 | 8, 360, 260, 200, 150, *([0] * 13))
s.sendall(struct.pack('<BBHIIIB3xI', 18, 0, 6 + 18, win, 40, 41, 32, 18) + hints)
s.sendall(struct.pack('<BxHI', 8, 2, win))   # MapWindow
log('__KEYPROBE up')
while True:
    e = recvn(32); t = e[0] & 0x7f
    if t == 2: log('__KEY %d %d' % (e[1], struct.unpack('<H', e[28:30])[0]))
    elif t == 4:
        x, y = struct.unpack('<hh', e[24:28]); log('__BTN %d %d %d' % (e[1], x, y))
        if e[1] == 3: log('__KEYDONE')
    elif t == 1: e += recvn(struct.unpack('<I', e[4:8])[0] * 4)   # a reply (none expected)
