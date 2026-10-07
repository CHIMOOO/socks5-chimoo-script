"""Build the self-contained installer without downloading code at runtime."""
from pathlib import Path

root = Path(__file__).resolve().parent
target = root / 'dist' / 'cm-install.sh'
parts = ['#!/usr/bin/env bash\nset -euo pipefail\numask 077\nWORK=$(mktemp -d)\ntrap \'rm -rf -- "$WORK"\' EXIT\n']
for name in ('common.py', 'monitor.py', 'cm.py', 'install.sh'):
    marker = 'CM_EMBED_' + name.replace('.', '_').upper()
    text = (root / name).read_text(encoding='utf-8').rstrip() + '\n'
    if marker in text.splitlines():
        raise ValueError('heredoc delimiter collision')
    parts.append(f'cat > "$WORK/{name}" <<\'{marker}\'\n{text}{marker}\n')
parts.append('bash "$WORK/install.sh" "$@"\n')
target.parent.mkdir(exist_ok=True)
target.write_text(''.join(parts), encoding='utf-8', newline='\n')
print(target)
