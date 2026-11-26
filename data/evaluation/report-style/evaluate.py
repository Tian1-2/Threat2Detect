"""Run a new, synthetic fixture against the Threat2Detect offline controller."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

# Hand-authored before running the evaluator. None means no result should be issued.
CASES = [
    ('S01', 'Audit notes recorded tasklist on the workstation.', 'tasklist', 'T1057',
     'observed', 'process', [(1, {'Image': 'tasklist.exe'}, 'hit'),
                             (1, {'Image': 'notepad.exe'}, 'miss')], 'hit', True),
    ('S02', 'The workstation audit recorded ipconfig without additional arguments.', 'ipconfig', 'T1016',
     'observed', 'network', [(1, {'Image': 'ipconfig.exe', 'CommandLine': 'ipconfig'}, 'miss')],
     'miss', True),
    ('S03', 'Audit notes recorded tasklist but no process telemetry was retained.', 'tasklist', 'T1057',
     'observed', 'process', [], None, True),
    ('S04', 'An analyst suspected tasklist was used but found no corroborating evidence.', 'tasklist', 'T1057',
     'unclear', 'process', [], None, False),
    ('S05', 'Audit notes recorded whoami on the workstation.', 'whoami', 'T1033',
     'observed', 'user', [(1, {'Image': 'whoami.exe'}, 'hit'),
                          (11, {'TargetFilename': 'whoami.exe'}, 'incompatible_logsource')],
     'hit', True),
]
RULES = {
    'process': ('10000000-0000-4000-8000-000000000001', 'T1057', 'tasklist', 'selection',
                {'selection': {'Image|endswith': 'tasklist.exe'}}),
    'network': ('10000000-0000-4000-8000-000000000002', 'T1016', 'ipconfig /all', 'selection',
                {'selection': {'Image|endswith': 'ipconfig.exe', 'CommandLine|contains': ' /all'}}),
    'user': ('10000000-0000-4000-8000-000000000003', 'T1033', 'whoami', 'by_image or by_name',
             {'by_image': {'Image|endswith': 'whoami.exe'}, 'by_name': {'OriginalFileName': 'whoami.exe'}}),
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--dataset', type=Path, help='Directory containing reports/ and reference.json')
    args = parser.parse_args()
    cases = CASES
    if args.dataset:
        references = json.loads((args.dataset / 'reference.json').read_text(encoding='utf-8'))
        cases = [
            (row['case_id'], (args.dataset / 'reports' / row['report']).read_text(encoding='utf-8').rstrip('\n'),
             row['quote'], row['technique'], row['fact_status'], row['rule'], row['samples'],
             row['expected_status'], row['expected_retrieval'])
            for row in references
        ]
    repo = args.repo.resolve()
    sys.path.insert(0, str(repo))
    import yaml
    from agent_poc import load_catalog
    from run_sigma_offline import run_rule
    from src.threat2detect.pipeline.controller import CaseController
    from validate_contract import validate_contract

    catalog = repo / 'data/attack/enterprise-attack-20.0.json'
    techniques = load_catalog(catalog)
    revision = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
    result = {
        'revision': revision, 'catalog_sha256': digest(catalog),
        'dataset_sha256': hashlib.sha256(json.dumps([cases, RULES], sort_keys=True).encode()).hexdigest(),
        'scope': 'Synthetic component benchmark. Confirmed handoffs and a three-rule synthetic library; zero model calls.',
        'unscored': ['model behavior extraction', 'model ATT&CK mapping', 'model report coverage',
                     'full-library ranking', 'candidate generation', 'clean checkout end-to-end inference'],
        'cases': [],
    }
    with TemporaryDirectory(prefix='fresh-eval-', dir=repo) as directory:
        base = Path(directory)
        rules = base / 'rules'
        rules.mkdir()
        paths = {}
        for key, (uid, tid, title, condition, selectors) in RULES.items():
            path = rules / (key + '.yml')
            path.write_text(yaml.safe_dump({
                'id': uid, 'title': title, 'status': 'test', 'tags': ['attack.' + tid.lower()],
                'logsource': {'product': 'windows', 'category': 'process_creation', 'service': 'sysmon'},
                'detection': {**selectors, 'condition': condition},
            }), encoding='utf-8')
            paths[key] = path
        result['rule_hashes'] = {key: digest(path) for key, path in paths.items()}
        for case_id, text, quote, tid, fact, key, samples, expected, should_retrieve in cases:
            path = base / (case_id + '.txt')
            path.write_text(text + '\n', encoding='utf-8')
            bid = case_id + '-B01'
            start = text.index(quote)
            annotation = {'confidence': 'high', 'origin': 'team_review', 'review_status': 'confirmed'}
            handoff = {
                'schema_version': '1.0', 'kind': 'case_handoff', 'case_id': case_id,
                'report': {'case_id': case_id, 'title': 'Synthetic audit ' + case_id,
                           'source_url': 'https://example.invalid/synthetic/' + case_id,
                           'input_path': path.relative_to(repo).as_posix(), 'input_sha256': digest(path),
                           'annotation_basis': 'answer_hidden_report_and_attack_catalog'},
                'attack_catalog': {'version': 'Enterprise 20.0', 'sha256': result['catalog_sha256'],
                                   'path': catalog.relative_to(repo).as_posix()},
                'behaviors': [{'behavior_id': bid, 'action': 'Review recorded command evidence', 'object': 'workstation',
                               'fact_status': fact, **annotation,
                               'evidence': {'quote': quote, 'char_start': start,
                                            'char_end': start + len(quote), 'pdf_page': None}}],
                'mappings': [{'mapping_id': case_id + '-M01', 'behavior_id': bid, 'technique_id': tid,
                              'technique_name': techniques[tid]['name'], 'rationale': 'Synthetic reference mapping',
                              'retrieved_candidate_ids': None, **annotation}] if fact == 'observed' else [],
                'telemetry': [], 'warnings': [],
            }
            observed_events = [
                {'event_uid': f'{case_id}:E{i:02d}', 'event_code': code,
                 'channel': 'Microsoft-Windows-Sysmon/Operational', 'host': 'fixture',
                 'timestamp_raw': None, 'raw_ref': f'synthetic:{case_id}:{i}', 'fields': fields}
                for i, (code, fields, _) in enumerate(samples, 1)
            ]
            events = {'schema_version': '1.0', 'kind': 'normalized_events', 'dataset_id': case_id,
                      'source_path': 'synthetic:' + case_id, 'parse_error_count': 0, 'items': observed_events}
            validate_contract(handoff, path)
            validate_contract(events, path)
            case = CaseController(base / case_id, handoff=handoff, events=events if samples else None,
                                  rules=base, controller='policy', skip_coverage=True).run()
            trace = [json.loads(line) for line in (base / case_id / 'trace.jsonl').read_text().splitlines()]
            target_id = RULES[key][0]
            matched = next((row for row in case['items'] if row['rule_id'] == target_id), None)
            event_scores = []
            for event, (_, _, expected_event) in zip(observed_events, samples):
                direct = run_rule(paths[key], target_id, {**events, 'items': [event]})
                event_scores.append({'id': event['event_uid'], 'event_code': event['event_code'],
                                     'fields': event['fields'], 'expected': expected_event,
                                     'actual': direct['status'], 'events_evaluated': direct['events_evaluated'],
                                     'events_skipped': direct['events_skipped']})
            actual = matched['sample_test_status'] if matched else None
            result['cases'].append({
                'case_id': case_id, 'report': text, 'reference_quote': quote, 'reference_technique': tid if fact == 'observed' else None,
                'workflow_status': case['workflow_status'], 'model_calls': case['model_calls_used'],
                'retrieval_expected': should_retrieve, 'retrieved_expected_rule': matched is not None,
                'executed_status_expected': expected, 'executed_status_actual': actual,
                'telemetry': matched.get('telemetry') if matched else None,
                'procedure_decision': matched.get('procedure_decision') if matched else None,
                'review_queue': case['review_queue'], 'events': event_scores,
                'trace_actions': [step.get('action', {}).get('tool') for step in trace],
            })
    rows = result['cases']
    events = [event for row in rows for event in row['events']]
    result['summary'] = {
        'cases': len(rows), 'retrieval_gate_agreements': sum(
            r['retrieval_expected'] == r['retrieved_expected_rule'] for r in rows),
        'controller_log_status_agreements': sum(
            r['executed_status_expected'] == r['executed_status_actual'] for r in rows),
        'direct_event_checks': len(events),
        'direct_event_agreements': sum(e['expected'] == e['actual'] for e in events),
        'controller_errors': sum(r['workflow_status'] == 'controller_error' for r in rows),
    }
    write(args.output, result)
    print(json.dumps(result['summary']))


if __name__ == '__main__':
    main()
