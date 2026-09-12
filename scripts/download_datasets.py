#!/usr/bin/env python
"""Stage the ATT&CK catalogue and adversary telemetry samples."""
from __future__ import annotations
 
import json
import sys
from pathlib import Path
from urllib.request import urlretrieve
 
ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / 'data' / 'raw'
ATTACK = RAW / 'attack'
TELEMETRY = RAW / 'telemetry'
 
ATTACK_STIX = (
    'https://raw.githubusercontent.com/mitre/cti/master/'
    'enterprise-attack/enterprise-attack.json'
)
 
REGISTERED = [
    ('EVTX-ATTACK-SAMPLES', 'https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES',
     'clone and place .evtx files under data/raw/telemetry/evtx/'),
    ('Security Datasets', 'https://securitydatasets.com/',
     'download the atomic/compound sets under data/raw/telemetry/mordor/'),
    ('CIC-IDS2017', 'https://www.unb.ca/cic/datasets/ids-2017.html',
     'request access, then extract CSVs under data/raw/telemetry/cicids/'),
]
 
 
def fetch_attack() -> None:
    ATTACK.mkdir(parents=True, exist_ok=True)
    target = ATTACK / 'enterprise-attack.json'
    if target.exists():
        print('[skip] enterprise-attack.json')
        return
    print('[get ] enterprise-attack.json (MITRE CTI, ~40 MB)')
    urlretrieve(ATTACK_STIX, target)
 
    # quick sanity summary so a failed download is obvious immediately
    data = json.loads(target.read_text())
    techniques = [o for o in data.get('objects', [])
                  if o.get('type') == 'attack-pattern' and not o.get('revoked')]
    print(f'       {len(techniques)} techniques available for loading')


def main() -> int:
    TELEMETRY.mkdir(parents=True, exist_ok=True)
    (TELEMETRY / '.gitkeep').touch()
 
    try:
        fetch_attack()
    except Exception as exc:
        print(f'[warn] ATT&CK download failed: {exc}')
        print('       seed_db.py falls back to a bundled technique subset.')
 
    print()
    print('Telemetry corpora requiring manual download:')
    for name, url, hint in REGISTERED:
        print(f'  - {name}: {url}')
        print(f'      {hint}')
    print()
    print('Telemetry contains hostnames, usernames and IPs — data/raw/telemetry/ is git-ignored.')
    print('Next: dvc add data/raw && dvc push')
    return 0
 
 
if __name__ == '__main__':
    sys.exit(main())