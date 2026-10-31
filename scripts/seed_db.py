#!/usr/bin/env python
"""Seed CyberSentry ATT&CK reference, detection rules, assets and demo detections."""
from __future__ import annotations
 
import ipaddress
import json
import os
import random
from datetime import datetime, timedelta, timezone
 
import psycopg
from psycopg.rows import dict_row
 
DSN = (
    f"host={os.getenv('DB_HOST', 'localhost')} port={os.getenv('DB_PORT', '5432')} "
    f"dbname={os.getenv('DB_NAME', 'cybersentry')} user={os.getenv('DB_USER', 'sentry')} "
    f"password={os.getenv('DB_PASS', 'sentry_dev_2026')}"
)
 
TACTICS = [
    ('TA0001', 'initial-access', 'Initial Access'),
    ('TA0002', 'execution', 'Execution'),
    ('TA0003', 'persistence', 'Persistence'),
    ('TA0006', 'credential-access', 'Credential Access'),
    ('TA0007', 'discovery', 'Discovery'),
    ('TA0011', 'command-and-control', 'Command and Control'),
    ('TA0010', 'exfiltration', 'Exfiltration'),
]
 
TECHNIQUES = [
    ('T1078', 'Valid Accounts', 'TA0001', None),
    ('T1110', 'Brute Force', 'TA0006', None),
    ('T1003', 'OS Credential Dumping', 'TA0006', None),
    ('T1003.001', 'LSASS Memory', 'TA0006', 'T1003'),
    ('T1059', 'Command and Scripting Interpreter', 'TA0002', None),
    ('T1059.001', 'PowerShell', 'TA0002', 'T1059'),
    ('T1071', 'Application Layer Protocol', 'TA0011', None),
    ('T1071.004', 'DNS', 'TA0011', 'T1071'),
    ('T1098', 'Account Manipulation', 'TA0003', None),
    ('T1046', 'Network Service Discovery', 'TA0007', None),
    ('T1041', 'Exfiltration Over C2 Channel', 'TA0010', None),
]
 
RULES = [
     ('DR001_BRUTE_FORCE', 1, 'Repeated failed authentication from a single source',
     'T1110', 'medium', '{"failures": 15, "window_minutes": 5}'),
    ('DR002_IMPOSSIBLE_TRAVEL', 1, 'Successful logins from impossible locations',
     'T1078', 'high', '{"max_kph": 900}'),
    ('DR003_LSASS_ACCESS', 1, 'Non-system process opened a handle to LSASS',
     'T1003.001', 'critical', '{}'),
    ('DR004_ENCODED_POWERSHELL', 1, 'PowerShell executed with an encoded command',
     'T1059.001', 'high', '{"min_length": 120}'),
    ('DR005_DNS_TUNNEL', 1, 'Anomalous DNS volume and entropy to a single domain',
     'T1071.004', 'high', '{"queries_per_minute": 60, "min_entropy": 3.5}'),
    ('DR006_CLOUD_KEY_CREATED', 1, 'New access key created for a privileged identity',
     'T1098', 'medium', '{}'),
    ('DR007_PORT_SCAN', 1, 'Single source contacted many ports on many hosts',
     'T1046', 'low', '{"unique_ports": 50}'),
    ('DR008_LARGE_EGRESS', 1, 'Unusual outbound data volume to an external address',
     'T1041', 'high', '{"mb_threshold": 500}'),
]
 
PLAYBOOKS = [
    ('PB_CRED_DUMP', 'Credential dumping containment', 'T1003.001',
     '["isolate_host", "collect_forensics", "disable_account", "notify_owner"]', True),
    ('PB_BRUTE_FORCE', 'Brute force response', 'T1110',
     '["block_ip", "notify_owner"]', False),
    ('PB_C2_DNS', 'DNS command and control', 'T1071.004',
     '["block_ip", "isolate_host", "collect_forensics"]', True),
]
 
SEVERITY_SCORE = {'info': 5, 'low': 20, 'medium': 45, 'high': 70, 'critical': 90}
 
 
def seed_reference(cur) -> None:
    cur.executemany('INSERT INTO attack_tactics (tactic_id, tactic_slug, tactic_name) '
                    'VALUES (%s,%s,%s) ON CONFLICT DO NOTHING', TACTICS)
    # parents first so the self-reference resolves
    for tid, name, tactic, parent in sorted(TECHNIQUES, key=lambda t: (t[3] is not None)):
        cur.execute(
            'INSERT INTO attack_techniques (technique_id, technique_name, tactic_id, '
            'parent_technique) VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING',
            (tid, name, tactic, parent),
        )
    cur.executemany(
        'INSERT INTO detection_rules (rule_code, version, title, technique_id, base_severity, '
        "params, author) VALUES (%s,%s,%s,%s,%s,%s::jsonb,'soc-engineering') "
        'ON CONFLICT DO NOTHING', RULES)
    cur.executemany(
        'INSERT INTO playbooks (playbook_id, title, trigger_technique, steps, '
        'requires_approval) VALUES (%s,%s,%s,%s::jsonb,%s) ON CONFLICT DO NOTHING', PLAYBOOKS)
 
 
def seed_estate(cur, n_assets: int = 60, n_identities: int = 40) -> tuple[list, list]:
    assets, identities = [], []
    for i in range(n_assets):
        atype = ('domain_controller' if i < 2 else
                 'server' if i < 14 else
                 'cloud_instance' if i < 24 else 'workstation')
        crit = ('crown_jewel' if atype == 'domain_controller' else
                'high' if atype == 'server' else
                random.choice(['low', 'medium', 'medium']))
        cur.execute(
            'INSERT INTO assets (host_id, hostname, asset_type, os_family, ip_address, '
            'business_unit, owner_email, criticality, is_internet_facing) '
            'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING asset_id',
            (f'HOST-{i:04d}', f'corp-{atype[:3]}-{i:03d}', atype,
             random.choice(['windows', 'linux']),
             str(ipaddress.IPv4Address(0x0A000000 + i)),
             random.choice(['finance', 'engineering', 'sales', 'it']),
             f'owner{i % 9}@corp.example', crit, atype == 'cloud_instance'),
        )
        assets.append(cur.fetchone()['asset_id'])
 
    for i in range(n_identities):
        privileged = i % 8 == 0
        cur.execute(
            'INSERT INTO identities (user_name, display_name, identity_type, is_privileged, '
            'department) VALUES (%s,%s,%s,%s,%s) RETURNING identity_id',
            (f'corp\\user{i:03d}', f'Demo User {i:03d}',
             'admin' if privileged else 'user', privileged,
             random.choice(['finance', 'engineering', 'sales', 'it'])),
        )
        identities.append(cur.fetchone()['identity_id'])
    return assets, identities
 
 
def seed_detections(cur, assets: list, identities: list, n: int = 300) -> None:
    now = datetime.now(timezone.utc)
    for i in range(n):
        rule = random.choice(RULES)
        severity = rule[4]
        asset_id = random.choice(assets)
        identity_id = random.choice(identities)
        detected_at = now - timedelta(minutes=random.randint(0, 60 * 24 * 7))
        bucket = detected_at.strftime('%Y%m%d%H%M')[:-1]   # 10-minute bucket
        dedup = f'{rule[0]}|{asset_id}|{bucket}|{i % 97}'
        cur.execute(
            'INSERT INTO detections (rule_code, rule_version, detected_at, asset_id, '
            'identity_id, source_ip, severity, risk_score, dedup_key, evidence_index, '
            'evidence_doc_id, detail) '
            'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb) ON CONFLICT DO NOTHING',
            (rule[0], rule[1], detected_at, asset_id, identity_id,
             str(ipaddress.IPv4Address(random.getrandbits(32))), severity,
             SEVERITY_SCORE[severity], dedup,
             f"sentry-events-{detected_at.strftime('%Y.%m.%d')}",
             f'doc-{i:06d}', json.dumps({'seeded': True, 'rule_title': rule[2]})),
        )
 
 
def main() -> None:
    random.seed(20260911)
    with psycopg.connect(DSN, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT COUNT(*) AS c FROM detection_rules')
            if cur.fetchone()['c'] > 0:
                print('already seeded — run `make reset` first to reseed')
                return
            seed_reference(cur)
            assets, identities = seed_estate(cur)
            seed_detections(cur, assets, identities)
            cur.execute(
                "INSERT INTO audit_log (actor, action, resource_type, resource_id, detail) "
                "VALUES ('seed_script','SEED','database','cybersentry','{\"milestone\": \"M1\"}')"
            )
        conn.commit()
    print('seeded: 7 tactics, 11 techniques, 8 rules, 3 playbooks, 60 assets, ~300 detections')
 
 
if __name__ == '__main__':
    main()