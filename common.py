"""Shared paths and atomic file writes; no third-party packages."""
import json
import os
from pathlib import Path
import tempfile

CONFIG = Path('/etc/gost-auto/config.json')
SETTINGS = Path('/etc/cm/monitor.json')
TOKEN = Path('/etc/cm/query-token')
DATABASE = Path('/var/lib/cm/traffic.sqlite')
LEGACY_DATABASE = Path('/var/lib/gost-traffic/traffic.sqlite')
UNIT = Path('/etc/systemd/system/gost.service')


def read_json(path, default=None):
    if not path.exists() and default is not None:
        return default
    return json.loads(path.read_text(encoding='utf-8'))


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def write_json(path, data):
    atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2) + '\n')
