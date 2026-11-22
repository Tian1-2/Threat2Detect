"""Build a small, traceable development fixture from existing OTRF events."""
import argparse
import json
import sys
import copy
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.threat2detect.contracts import ROOT, validate_contract
from src.threat2detect.telemetry.otrf import DEFAULT_SOURCE, normalize


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output_dir', type=Path)
    parser.add_argument('--scenario', choices=['lsass', 'bits'], default='lsass')
    parser.add_argument('--case-agent-demo', action='store_true', help='Also prepare a report handoff and explicit generation plan (BITS only)')
    args = parser.parse_args()
    if args.case_agent_demo and args.scenario != 'bits':
        raise ValueError('--case-agent-demo currently requires --scenario bits')
    out = args.output_dir.resolve()
    if not out.is_relative_to(ROOT) or (out.exists() and any(out.iterdir())):
        raise ValueError('Use an empty output directory inside the project')
    source = DEFAULT_SOURCE if args.scenario == 'lsass' else ROOT / 'data/Security-Datasets/datasets/atomic/windows/defense_evasion/host/cmd_bitsadmin_download_psh_script.zip'
    did = 'OTRF-LSASS_campaign_06' if args.scenario == 'lsass' else 'OTRF-BITS-download'
    lines = (1727, 33808) if args.scenario == 'lsass' else (149, 118)
    events = normalize(source, did, {10} if args.scenario == 'lsass' else {1})
    chosen = {f"{events['dataset_id']}:L{n}" for n in lines}
    events['items'] = [e for e in events['items'] if e['event_uid'] in chosen]
    if len(events['items']) != 2:
        raise ValueError('Expected the two scenario development events')
    req = json.loads((ROOT / 'data/annotations/rule_generation_request_example.json').read_text())
    req['detection_goal'] = ('Draft a Windows Sysmon process-access rule for LSASS access with GrantedAccess '
                             '0x1FFFFF. This is a narrow development scenario, not a universal dump detector.')
    req['required_conditions'] = [
        {'field': 'TargetImage', 'modifier': 'endswith', 'value': '\\lsass.exe'},
        {'field': 'GrantedAccess', 'modifier': 'equals', 'value': '0x1FFFFF'},
    ]
    if args.scenario == 'bits':
        req.update(scenario_id='manual-bits-download-demo-01',
                   behavior='Download payloads with bitsadmin; only the transfer-command variant is selected for this development goal.',
                   attack_ids=['T1105', 'T1197'],
                   logsource={'product': 'windows', 'category': 'process_creation', 'service': None},
                   available_fields=['Image', 'CommandLine', 'ParentImage'],
                   detection_goal='Narrow goal: Image ends with \\bitsadmin.exe AND CommandLine contains the literal flag substring " /transfer ". Do not claim maliciousness or coverage of other BITS methods.',
                   required_conditions=[{'field': 'Image', 'modifier': 'endswith', 'value': '\\bitsadmin.exe'},
                                        {'field': 'CommandLine', 'modifier': 'contains', 'value': ' /transfer '}])
    for key, line in [('positive_event_refs', lines[1]), ('negative_event_refs', lines[0])]:
        req[key] = [{'dataset_id': events['dataset_id'], 'event_uid': f"{events['dataset_id']}:L{line}",
                     'provenance': 'public_attack'}]
    req['sample_limitations'] = [f'L{lines[0]} is a background candidate in a public attack simulation, not independently proven benign.',
                                'Negative means expected nonmatch for this narrow goal, not an event benignness label.',
                                'Both events are development samples; do not estimate false-positive rate.']
    req['evidence_items'] = [{'evidence_id': 'goal', 'kind': 'manual_goal', 'text': req['detection_goal'],
                              'source_ref': 'Manually specified development scope, not an extracted report claim.'}]
    if args.scenario == 'bits':
        req['evidence_items'].append({'evidence_id': 'report', 'kind': 'report_fact',
            'text': 'The cyber threat actors used PowerShell and bits admin getfile to download payloads.',
            'source_ref': 'data/reports/cisa-aa25-266a-input.txt#PDF-page-9'})
    req['unknown_information'] = ['Exact malicious source URL, payload filename, parent process and production benignness are unknown.',
                                  'BITS /transfer is a manually selected variant; the CISA report does not establish that flag.' if args.scenario == 'bits' else 'Source process identity must not become an extra restriction.']
    req['allowed_assumption_ids'] = []
    # Final-only synthetic boundary tests: never substituted for independent public logs.
    positive = next(e for e in events['items'] if e['event_uid'].endswith(f':L{lines[1]}'))
    boundary = {'schema_version': '1.0', 'kind': 'normalized_events',
                'dataset_id': 'synthetic-' + args.scenario + '-boundary-v1',
                'source_path': 'synthetic:prepare_rule_generation_demo', 'parse_error_count': 0, 'items': []}
    refs = {'positive_event_refs': [], 'negative_event_refs': [], 'independence': 'synthetic_boundary',
            'limitations': ['Synthetic boundary evaluation only; not independent public attack/benign validation.',
                            'If these results inform later tuning, this set is no longer held out for that later version.']}
    if args.scenario == 'bits':
        cases = [('positive', {'Image': r'D:\Tools\bitsadmin.exe', 'CommandLine': r'bitsadmin.exe /transfer job https://example.invalid/sample D:\tmp\sample'}),
                 ('negative', {'Image': r'C:\Windows\System32\cmd.exe', 'CommandLine': 'cmd.exe /transfer job'}),
                 ('negative', {'Image': r'C:\Windows\System32\bitsadmin.exe', 'CommandLine': 'bitsadmin.exe /list'}),
                 ('negative', {'Image': r'C:\Windows\System32\bitsadmin.exe'})]
    else:
        cases = [('positive', {'SourceImage': r'D:\Tools\other-tool.exe', 'TargetImage': r'C:\Windows\System32\lsass.exe', 'GrantedAccess': '0x1FFFFF'}),
                 ('negative', {'TargetImage': r'C:\Windows\System32\services.exe', 'GrantedAccess': '0x1FFFFF'}),
                 ('negative', {'TargetImage': r'C:\Windows\System32\lsass.exe', 'GrantedAccess': '0x1400'}),
                 ('negative', {'GrantedAccess': '0x1FFFFF'})]
    for i, (label, fields) in enumerate(cases, 1):
        event = copy.deepcopy(positive)
        event.update(event_uid=f"{boundary['dataset_id']}:S{i}", fields=fields,
                     timestamp_raw=None, host='SYNTHETIC', raw_ref=f'synthetic:{args.scenario}:S{i}')
        boundary['items'].append(event)
        refs[label + '_event_refs'].append({'dataset_id': boundary['dataset_id'], 'event_uid': event['event_uid'], 'provenance': 'synthetic'})
    validate_contract(req, out / 'request.json')
    validate_contract(events, out / 'events.json')
    validate_contract(boundary, out / 'evaluation_events.json')
    out.mkdir(parents=True, exist_ok=True)
    for name, value in [('request', req), ('events', events), ('evaluation_events', boundary), ('evaluation_refs', refs)]:
        (out / f'{name}.json').write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    if args.case_agent_demo:
        handoff = json.loads((ROOT / 'data/AA25-266A/AA25-266A/case_handoff_reviewed.json').read_text())
        bid = 'AA25-266A-P020'
        handoff['behaviors'] = [b for b in handoff['behaviors'] if b['behavior_id'] == bid]
        handoff['mappings'] = [m for m in handoff['mappings'] if m['behavior_id'] == bid]
        handoff['telemetry'] = [t for t in handoff['telemetry'] if t['behavior_id'] == bid]
        handoff['warnings'].append('Manual BITS transfer variant demonstration; report does not establish /transfer. Behavior remains draft.')
        validate_contract(handoff, out / 'handoff.json')
        plan = [{'behavior_id': bid, 'trigger': 'explicit_request',
                 'request_path': (out / 'request.json').relative_to(ROOT).as_posix(),
                 'events_paths': [(out / 'events.json').relative_to(ROOT).as_posix()],
                 'evaluation_refs_path': (out / 'evaluation_refs.json').relative_to(ROOT).as_posix(),
                 'evaluation_events_paths': [(out / 'evaluation_events.json').relative_to(ROOT).as_posix()]}]
        for name, value in [('handoff', handoff), ('generation_plan', plan)]:
            (out / f'{name}.json').write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(out)


if __name__ == '__main__':
    main()
