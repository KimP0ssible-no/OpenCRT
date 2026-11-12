#!/bin/sh
# Write lang/opencrt.pot again: the Slint UI's @tr texts, then the Rust code's
# tr! texts. Needs slint-tr-extractor (cargo install slint-tr-extractor) and python3.
set -eu
cd "$(dirname "$0")/../../.."
pot=crates/opencrt/lang/opencrt.pot
slint-tr-extractor --no-default-translation-context --package-name OpenCRT -o "$pot" crates/opencrt/ui/*.slint
python3 - "$pot" crates/opencrt/src/*.rs <<'PY'
import re, sys
pot, sources = sys.argv[1], sys.argv[2:]
known = set(re.findall(r'^msgid "((?:[^"\\]|\\.)*)"$', open(pot, encoding="utf-8").read(), re.M))
texts = {}
for path in sources:
    for n, line in enumerate(open(path, encoding="utf-8"), 1):
        for m in re.finditer(r'(?<![A-Za-z0-9_])tr!\("((?:[^"\\]|\\.)*)"', line):
            texts.setdefault(m.group(1), []).append(f"{path}:{n}")
with open(pot, "a", encoding="utf-8") as out:
    for text, places in texts.items():
        if text not in known:
            out.write(f'\n#: {" ".join(places)}\nmsgid "{text}"\nmsgstr ""\n')
PY
