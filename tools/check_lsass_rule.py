"""Manual field check for NVISO sysmon_lsass_memdump.yml, not a Sigma engine."""
import json
from collections import Counter
from pathlib import Path
import zipfile

path = Path('data/Security-Datasets/datasets/compound/LSASS_campaign_06/metasploit_outflank-dumpert_lsass_memory_dump.json')
counts = Counter()
source = path if path.exists() else path.with_suffix('.zip')
archive = zipfile.ZipFile(source) if source.suffix == '.zip' else None
stream = (line.decode('utf-8') for line in archive.open(archive.namelist()[0])) if archive else source.open('r', encoding='utf-8')
try:
    for line in stream:
        event = json.loads(line)
        counts['all'] += 1
        if event.get('Channel') != 'Microsoft-Windows-Sysmon/Operational' or event.get('EventID') != 10:
            continue
        counts['event10'] += 1
        fields = dict(part.split(': ', 1) for part in event.get('Message', '').splitlines() if ': ' in part)
        if fields.get('TargetImage', '').lower() != r'c:\windows\system32\lsass.exe':
            continue
        counts['lsass'] += 1
        if fields.get('GrantedAccess', '').lower() != '0x1fffff':
            continue
        counts['access'] += 1
        trace = fields.get('CallTrace', '').lower()
        if not ('dbghelp.dll' in trace or 'dbgcore.dll' in trace):
            continue
        counts['match'] += 1
        print(event.get('TimeCreated'), fields.get('SourceImage'), fields.get('TargetImage'), fields.get('GrantedAccess'), 'dbgcore.dll' if 'dbgcore.dll' in trace else 'dbghelp.dll')
finally:
    if archive:
        archive.close()
    else:
        stream.close()
print(counts)
