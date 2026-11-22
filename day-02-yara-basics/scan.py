import sys
from pathlib import Path
import yara

rules = yara.compile(filepath="rules.yar")
target = Path(sys.argv[1] if len(sys.argv) > 1 else "samples")

for f in sorted(target.rglob("*")):
    if f.is_file():
        matches = rules.match(str(f))
        names = ", ".join(m.rule for m in matches) or "no match"
        print(f"{f.name:28} -> {names}")
