# Raw X11 protocol client (no libX11): proves an X server answers and draws.
# Connects to 127.0.0.1:6000+display, reads the setup reply, creates a 200x100 window,
# maps it, fills it red with a GC, reads the pixels back with GetImage and checks them.
# Prints __X11OK on success. Retries the connection while the server starts.
import socket, struct, sys, time

disp = int(sys.argv[1]) if len(sys.argv) > 1 else 0
t0 = time.time()
s = None
while time.time() - t0 < 60:
    try:
        s = socket.create_connection(('127.0.0.1', 6000 + disp), timeout=10); break
    except OSError as e:
        err = e; time.sleep(0.5)
if s is None:
    print('connect failed:', err); sys.exit(1)
print('connected after %.1fs' % (time.time() - t0))

def recvn(n):
    b = b''
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c: raise EOFError('server closed after %d of %d bytes' % (len(b), n))
        b += c
    return b

s.sendall(struct.pack('<BxHHHHxx', ord('l'), 11, 0, 0, 0))
head = recvn(8)
status, _, major, minor, extra = struct.unpack('<BBHHH', head)
body = recvn(extra * 4)
if status != 1:
    print('setup refused:', body[:head[1]]); sys.exit(1)
(release, rid_base, rid_mask, motion, vlen, maxreq, nscreens, nformats,
 img_order, bm_order, bm_unit, bm_pad, minkc, maxkc) = struct.unpack('<IIIIHHBBBBBBBB4x', body[:32])
vendor = body[32:32 + vlen].decode('latin1')
off = 32 + ((vlen + 3) & ~3) + 8 * nformats
root, cmap, white, black, inmask, wpx, hpx, wmm, hmm, minm, maxm, rvis, bstore, saveu, rdepth, ndepths = \
    struct.unpack('<IIIIIHHHHHHIBBBB', body[off:off + 40])
print('X%d.%d vendor %r release %d screens %d root 0x%x %dx%d depth %d' % (major, minor, vendor, release, nscreens, root, wpx, hpx, rdepth))

rid = [rid_base]
def newid():
    rid[0] += 1; return rid[0]
win, gc = newid(), newid()
# CreateWindow: depth=CopyFromParent, x=20 y=20 200x100 border 0, InputOutput, visual CopyFromParent, CWBackPixel
s.sendall(struct.pack('<BBHIIhhHHHHII', 1, 0, 9, win, root, 20, 20, 200, 100, 0, 1, 0, 0x2) + struct.pack('<I', white))
s.sendall(struct.pack('<BxHI', 8, 2, win))                                     # MapWindow
s.sendall(struct.pack('<BxHIII', 55, 5, gc, win, 0x4) + struct.pack('<I', 0xff0000))  # CreateGC fg=red
s.sendall(struct.pack('<BxHII', 70, 5, win, gc) + struct.pack('<hhHH', 0, 0, 200, 100))  # PolyFillRectangle
# GetImage ZPixmap of the root window where the window sits, then check the middle pixel
s.sendall(struct.pack('<BBHIhhHHI', 73, 2, 5, root, 20, 20, 200, 100, 0xffffffff))
while True:
    h = recvn(32)
    if h[0] == 0:
        print('X error code %d major %d' % (h[1], h[10])); sys.exit(1)
    if h[0] == 1: break
    # an event: skip
rlen = struct.unpack('<I', h[4:8])[0]
data = recvn(rlen * 4)
bpl = len(data) // 100
px = struct.unpack('<I', data[50 * bpl + 100 * 4: 50 * bpl + 100 * 4 + 4])[0] & 0xffffff
print('GetImage depth %d, %d bytes, pixel(120,70) = 0x%06x' % (h[1], len(data), px))
print('__X11OK' if px == 0xff0000 else '__X11BAD')
