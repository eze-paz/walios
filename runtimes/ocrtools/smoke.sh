#!/usr/bin/env bash
# Smoke test of tesseract on the node WALI host (eze-paz/walios host/host.js via $WALI_RUN):
# known Spanish, Catalan and English text rendered to PNG (one clean, one rotated + noisy JPEG),
# OCR'd with the tessdata_fast models, checked word by word. The packages' usr/share must be
# under /usr/share on the runner (the workflow copies it), as `apk add` mounts it in walios.
#   smoke.sh <pkg dir with tesseract/usr/...>
set -uo pipefail
PK=$(realpath "${1:?pkg dir}")
RUN=${WALI_RUN:-wali-run}
B=$PK/tesseract/usr/bin
T=$(mktemp -d); cd "$T"
python3 - <<'EOF'
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import random
F = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
texts = {
  'spa': ['Informe de puesta en marcha', 'Presión de trabajo fijada en 7,5 bar', 'Generador de nitrógeno PSA'],
  'cat': ['Informe de posada en marxa', 'Pressió de treball fixada a 7,5 bar', 'Generador de nitrogen del celler'],
  'eng': ['Commissioning report', 'Working pressure set to 7.5 bar', 'Nitrogen generator purity 99.5%'],
}
for lang, lines in texts.items():
    im = Image.new('L', (1400, 80 + 70 * len(lines)), 255); d = ImageDraw.Draw(im); f = ImageFont.truetype(F, 40)
    for i, t in enumerate(lines): d.text((40, 40 + 70 * i), t, font=f, fill=0)
    im.save(f'{lang}.png')
    open(f'{lang}.txt', 'w').write('\n'.join(lines))
# a "scan": slight rotation, blur and noise, as JPEG
im = Image.open('spa.png').rotate(1.5, expand=True, fillcolor=255).filter(ImageFilter.GaussianBlur(0.8))
px = im.load(); random.seed(1)
for _ in range(4000): px[random.randrange(im.width), random.randrange(im.height)] = random.choice((0, 128, 255))
im.convert('RGB').save('scan.jpg', quality=70)
EOF
fail=0
t() { echo; echo "\$ $*"; "$@"; local rc=$?; echo "[exit $rc]"; [ $rc = 0 ] || fail=1; }
words() {   # words <expected.txt> <got.txt>: the share of expected words found (case-insensitive)
  python3 - "$1" "$2" <<'EOF'
import sys, re
exp = re.findall(r'\w[\w,.%]*', open(sys.argv[1]).read().lower())
got = open(sys.argv[2]).read().lower()
hit = [w for w in exp if w in got]
print(f'{len(hit)}/{len(exp)} words', 'missing:', [w for w in exp if w not in got])
sys.exit(0 if len(hit) >= 0.9 * len(exp) else 1)
EOF
}
t $RUN $B/tesseract --version
t $RUN $B/tesseract --list-langs
for l in spa cat eng; do
  t $RUN $B/tesseract $l.png out-$l -l $l
  cat out-$l.txt
  words $l.txt out-$l.txt || { echo "CHECK: $l OCR below 90% of the words"; fail=1; }
done
t $RUN $B/tesseract scan.jpg out-scan -l spa+cat+eng
cat out-scan.txt
words spa.txt out-scan.txt || { echo "CHECK: noisy rotated JPEG below 90% of the words"; fail=1; }
t $RUN $B/tesseract eng.png out-tsv -l eng tsv
head -n 5 out-tsv.tsv
[ "$(awk -F'\t' 'NR>1 && $12!="" && $11>=0' out-tsv.tsv | wc -l)" -ge 5 ] || { echo "CHECK: tsv has no word rows with confidences"; fail=1; }
t $RUN $B/tesseract eng.png - -l eng
echo; [ $fail = 0 ] && echo "SMOKE tesseract: PASS" || echo "SMOKE tesseract: FAIL"
exit $fail
