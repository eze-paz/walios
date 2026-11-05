#!/usr/bin/env bash
# Smoke test of the PDF tools on the node WALI host (eze-paz/walios host/host.js via
# $WALI_RUN), against a 3-page ReportLab PDF with an embedded PNG and JPEG and non-embedded
# Helvetica/Times text -- the kind of file walios users hand these tools.
#   smoke.sh <pkg dir with <name>/usr/...> <component>
# Prints each command and its real output; exits non-zero on the first failed check.
set -uo pipefail
PK=$(realpath "${1:?pkg dir}"); WHAT=${2:?component}
RUN=${WALI_RUN:-wali-run}
T=$(mktemp -d); cd "$T"
python3 - <<'EOF'
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from PIL import Image, ImageDraw
im = Image.new('RGB', (320, 200), (30, 90, 200)); d = ImageDraw.Draw(im)
d.ellipse((60, 30, 260, 170), fill=(250, 200, 20)); im.save('product.png')
im2 = Image.new('RGB', (240, 160), (200, 40, 40)); ImageDraw.Draw(im2).rectangle((40, 40, 200, 120), fill=(255, 255, 255)); im2.save('logo.jpg', quality=90)
c = canvas.Canvas('ficha.pdf', pagesize=A4)
for i in range(3):
    c.setFont('Helvetica-Bold', 22); c.drawString(72, 770, f'Ficha tecnica - pagina {i + 1}')
    c.setFont('Times-Roman', 12); c.drawString(72, 740, 'Generador de nitrogeno PSA, caudal 25 Nm3/h, pureza 99.99%')
    c.drawImage('product.png' if i != 1 else 'logo.jpg', 72, 420, width=320, height=200)
    c.showPage()
c.save()
EOF
ls -la ficha.pdf
fail=0
t() { echo; echo "\$ $*"; "$@"; local rc=$?; echo "[exit $rc]"; [ $rc = 0 ] || fail=1; }
png() { python3 -c 'import sys
from PIL import Image
for f in sys.argv[1:]:
    im = Image.open(f); px = im.convert("RGB").getcolors(1 << 24) or []
    print(f, im.size, im.mode, "colors:", len(px))' "$@"; }
B=$PK/$WHAT/usr/bin
case "$WHAT" in
  poppler-utils)
    t $RUN $B/pdfinfo ficha.pdf
    t $RUN $B/pdffonts ficha.pdf
    t $RUN $B/pdftotext -layout ficha.pdf out.txt && cat out.txt
    grep -q 'pagina 3' out.txt || { echo "CHECK: pdftotext lost page 3"; fail=1; }
    t $RUN $B/pdfimages -list ficha.pdf
    t $RUN $B/pdfimages -png ficha.pdf img; ls -la img-*; png img-*.png
    [ "$(ls img-*.png | wc -l)" -ge 3 ] || { echo "CHECK: pdfimages extracted < 3 images"; fail=1; }
    t $RUN $B/pdftoppm -png -r 60 ficha.pdf pg 2>ppm.err; cat ppm.err; ls -la pg-*; png pg-*.png
    [ "$(ls pg-*.png | wc -l)" = 3 ] || { echo "CHECK: pdftoppm did not render 3 pages"; fail=1; }
    grep -qi "couldn't find a font" ppm.err && { echo "CHECK: base-14 font substitution failed"; fail=1; }
    t $RUN $B/pdfseparate ficha.pdf sep-%d.pdf; ls sep-*.pdf
    t $RUN $B/pdfunite sep-1.pdf sep-3.pdf united.pdf && $RUN $B/pdfinfo united.pdf | grep Pages
    ;;
  mupdf-tools)
    t $RUN $B/mutool info ficha.pdf
    t $RUN $B/mutool draw -q -r 60 -o mpg-%d.png ficha.pdf; ls -la mpg-*; png mpg-*.png
    [ "$(ls mpg-*.png | wc -l)" = 3 ] || { echo "CHECK: mutool draw did not render 3 pages"; fail=1; }
    t $RUN $B/mutool draw -F txt -o - ficha.pdf
    mkdir ex && cd ex && t $RUN $B/mutool extract ../ficha.pdf; ls -la; cd ..
    t $RUN $B/mutool merge -o merged.pdf ficha.pdf 1,3 && $RUN $B/mutool info merged.pdf | grep -i pages
    ;;
  qpdf)
    t $RUN $B/qpdf --version
    t $RUN $B/qpdf --check ficha.pdf
    t $RUN $B/qpdf ficha.pdf --pages . 2-3 -- part.pdf && $RUN $B/qpdf --show-npages part.pdf
    t $RUN $B/qpdf --qdf --object-streams=disable ficha.pdf qdf.pdf && ls -la qdf.pdf
    t $RUN $B/qpdf --encrypt user owner 256 -- ficha.pdf enc.pdf && $RUN $B/qpdf --password=user --decrypt enc.pdf dec.pdf && $RUN $B/qpdf --check dec.pdf | tail -2
    ;;
esac
echo; [ $fail = 0 ] && echo "SMOKE $WHAT: PASS" || echo "SMOKE $WHAT: FAIL"
exit $fail
