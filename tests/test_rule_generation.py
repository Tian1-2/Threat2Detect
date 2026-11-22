import copy
import json
from pathlib import Path

import pytest

from src.threat2detect.rule_generation import generator as gen
from src.threat2detect.sigma import executor as engine


RULE = r"""title: Suspicious LSASS Access Candidate
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess: '0x1FFFFF'
  condition: selection
level: medium
"""


@pytest.fixture
def setup(tmp_path, monkeypatch):
    request = json.loads((gen.ROOT / 'data/annotations/rule_generation_request_example.json').read_text())
    monkeypatch.setattr(gen, 'ROOT', tmp_path)
    monkeypatch.setattr(engine, 'ROOT', tmp_path)
    request['positive_event_refs'] = [{'dataset_id': 'sample', 'event_uid': 'p', 'provenance': 'synthetic'}]
    request['negative_event_refs'] = [{'dataset_id': 'sample', 'event_uid': 'n', 'provenance': 'synthetic'}]
    def event(uid, access):
        return {'event_uid': uid, 'event_code': 10, 'channel': 'Microsoft-Windows-Sysmon/Operational',
                'fields': {'TargetImage': r'C:\Windows\System32\lsass.exe', 'GrantedAccess': access}}
    return request, {'sample': {'dataset_id': 'sample', 'items': [event('p', '0x1FFFFF'), event('n', '0x1400')]}}, tmp_path


def test_real_executor_and_missing_reference(setup):
    req, datasets, out = setup
    result = gen.generate(req, out / 'valid', datasets, candidate=RULE)
    assert result['parse_status'] == 'valid'
    assert result['positive_tests'][0]['matched_event_uids'] == ['p']
    assert result['negative_tests'][0]['status'] == 'miss'
    assert result['review_status'] == 'draft'
    assert result['generation_mode'] == 'supplied_candidate'
    missing = gen.generate(req, out / 'missing', {}, candidate=RULE)
    assert missing['positive_tests'][0]['status'] == 'not_tested'
    assert missing['positive_tests'][0]['tested_event_uids'] == []


def test_feedback_revision_and_budget(setup):
    req, datasets, out = setup
    calls = []
    def propose(payload, feedback):
        assert 'positive_event_refs' not in payload
        calls.append(feedback)
        rule = RULE.replace("'0x1FFFFF'", "'0x1400'") if len(calls) == 1 else RULE
        return {'sigma_yaml': rule, 'limitations': []}
    result = gen.generate(req, out / 'revised', datasets, propose=propose)
    assert len(calls) == 2 and calls[1]
    assert result['positive_tests'][0]['status'] == 'hit'
    failed = gen.generate(req, out / 'budget', datasets, propose=lambda *_: {
        'sigma_yaml': RULE.replace("'0x1FFFFF'", "'0x1400'"), 'limitations': []}, max_attempts=2)
    assert failed['positive_tests'][0]['status'] == 'miss'
    assert any('budget exhausted' in s for s in failed['limitations'])


@pytest.mark.parametrize('rule,status', [
    (RULE.replace('GrantedAccess:', 'InventedField:'), 'invalid'),
    (RULE.replace('endswith', 'base64'), 'unsupported_syntax'),
    (RULE.replace('condition: selection', 'condition: missing_selector'), 'unsupported_syntax'),
    (RULE.replace('category: process_access', 'category: process_creation'), 'invalid'),
    ('title: [unterminated', 'invalid'),
    (RULE.replace("'0x1FFFFF'", "'*FFFF*'"), 'unsupported_syntax'),
    (RULE.replace('  condition: selection', '  condition: selection\n  condition: missing'), 'invalid'),
    (RULE.replace('endswith', 'endswith|contains'), 'unsupported_syntax'),
])
def test_reject_before_execution_without_samples(setup, rule, status):
    req, _, out = setup
    result = gen.generate(req, out / 'invalid', candidate=rule)
    assert result['parse_status'] == status
    assert result['candidate_yaml_path'] is None


def test_non_sysmon_and_no_compatible_events(setup):
    req, datasets, out = setup
    datasets['sample']['items'][0]['channel'] = 'Security'
    datasets['sample']['items'][1]['event_code'] = 1
    result = gen.generate(req, out / 'incompatible', datasets, candidate=RULE)
    assert all(row['status'] == 'not_tested' for row in result['positive_tests'] + result['negative_tests'])


def test_failures_are_recorded_and_old_runs_preserved(setup):
    req, datasets, out = setup
    def unavailable(*_):
        raise RuntimeError('model unavailable')
    result = gen.generate(req, out / 'failure', datasets, propose=unavailable, max_attempts=1)
    assert result['parse_status'] == 'invalid'
    assert result['candidate_yaml_path'] is None
    assert (out / 'failure/trace.json').is_file()
    with pytest.raises(ValueError, match='empty output'):
        gen.generate(req, out / 'failure', candidate=RULE)
    req['negative_event_refs'] = copy.deepcopy(req['positive_event_refs'])
    with pytest.raises(ValueError, match='both a positive'):
        gen.generate(req, out / 'overlap', candidate=RULE)


def test_mandatory_constraints_reject_sample_passing_but_overbroad_rules(setup):
    req, datasets, out = setup
    req['required_conditions'] = [
        {'field': 'TargetImage', 'modifier': 'endswith', 'value': r'\lsass.exe'},
        {'field': 'GrantedAccess', 'modifier': 'equals', 'value': '0x1FFFFF'},
    ]
    good = gen.generate(req, out / 'constrained', datasets, candidate=RULE)
    assert good['validation_outcome'] == 'passed_development_samples'
    bad = gen.generate(req, out / 'overbroad', datasets, candidate=RULE.replace(
        "    TargetImage|endswith: '\\lsass.exe'\n", ''))
    assert bad['parse_status'] == 'invalid'
    assert any('mandatory condition' in s for s in bad['limitations'])


def test_structured_model_proposal_is_compiled_and_executed(setup):
    req, datasets, out = setup
    result = gen.generate(req, out / 'structured', datasets, propose=lambda *_: {
        'title': 'LSASS candidate', 'combine': 'and', 'limitations': [], 'clauses': [
            {'field': 'TargetImage', 'modifier': 'endswith', 'values': [r'\lsass.exe']},
            {'field': 'GrantedAccess', 'modifier': 'equals', 'values': ['0x1FFFFF']},
        ]})
    assert result['validation_outcome'] == 'passed_development_samples'
    assert (out / 'structured/model-spec-1.json').is_file()


def test_condition_feedback_identifies_extra_restriction_without_leaking_event_values(setup):
    req, datasets, out = setup
    calls = []
    def propose(payload, feedback):
        calls.append((payload, feedback))
        return {'sigma_yaml': RULE.replace('    GrantedAccess:', "    SourceImage|endswith: '\\invented.exe'\n    GrantedAccess:")
                if len(calls) == 1 else RULE, 'limitations': []}
    result = gen.generate(req, out / 'conditions', datasets, propose=propose)
    assert result['positive_tests'][0]['status'] == 'hit'
    assert 'selection.SourceImage=missing' in str(calls[1][1])
    assert 'sample:p' not in str(calls[1][1])
    assert 'C:\\Windows' not in str(calls[1][1])


def test_evidence_ids_are_checked_and_attribution_persisted(setup):
    req, datasets, out = setup
    req['evidence_items'] = [{'evidence_id': 'goal', 'kind': 'manual_goal', 'text': 'LSASS access goal'}]
    proposal = {'title': 'candidate', 'combine': 'and', 'limitations': [], 'clauses': [
        {'field': 'TargetImage', 'modifier': 'endswith', 'values': [r'\lsass.exe'],
         'evidence_ids': ['goal'], 'explanation': 'Explicitly requested target.'},
        {'field': 'GrantedAccess', 'modifier': 'equals', 'values': ['0x1FFFFF'],
         'evidence_ids': ['goal'], 'explanation': 'Manually specified access mask.'},
    ]}
    result = gen.generate(req, out / 'evidence', datasets, propose=lambda *_: proposal)
    assert result['condition_basis'][0]['evidence_ids'] == ['goal']
    assert result['condition_basis'][0]['semantic_support'] == 'requires_human_review'
    proposal['clauses'][0]['evidence_ids'] = ['nonexistent']
    bad = gen.generate(req, out / 'bad-evidence', datasets, propose=lambda *_: proposal, max_attempts=1)
    assert bad['parse_status'] == 'invalid'
    req['evidence_items'][0]['kind'] = 'assumption'
    with pytest.raises(ValueError, match='Assumption'):
        gen.generate(req, out / 'assumption', candidate=RULE)


def evaluation_fixture(datasets):
    evaluation = {'independence': 'synthetic_boundary', 'limitations': [],
                  'positive_event_refs': [{'dataset_id': 'sealed', 'event_uid': 'sealed-p', 'provenance': 'synthetic'}],
                  'negative_event_refs': [{'dataset_id': 'sealed', 'event_uid': 'sealed-n', 'provenance': 'synthetic'}]}
    sealed = copy.deepcopy(datasets['sample'])
    sealed.update(dataset_id='sealed', source_path='synthetic:sealed')
    for i, e in enumerate(sealed['items']):
        e['event_uid'] = ['sealed-p', 'sealed-n'][i]
        e['fields']['SourceImage'] = 'sealed-marker-never-send-to-model'
    return evaluation, {'sealed': sealed}


def test_holdout_failure_never_revises_or_leaks_into_model(setup):
    req, datasets, out = setup
    evaluation, sealed = evaluation_fixture(datasets)
    # This is deliberately an expected hit on a nonmatching target to exercise evaluation failure.
    sealed['sealed']['items'][0]['fields']['TargetImage'] = r'C:\Windows\services.exe'
    calls = []
    def propose(payload, feedback):
        assert 'sealed' not in str(payload) + str(feedback)
        calls.append(1)
        return {'sigma_yaml': RULE, 'limitations': []}
    result = gen.generate(req, out / 'evaluation', datasets, propose=propose,
                          evaluation=evaluation, evaluation_datasets=sealed)
    assert len(calls) == 1
    assert result['validation_outcome'] == 'passed_development_samples'
    assert result['evaluation_summary']['outcome'] == 'failed'
    report = json.loads((out / 'evaluation/evaluation.json').read_text())
    assert report['used_for_revision'] is False
    assert report['candidate_yaml_sha256'] == result['candidate_yaml_sha256']


def test_holdout_overlap_and_renamed_copies_rejected(setup):
    req, datasets, out = setup
    evaluation, sealed = evaluation_fixture(datasets)
    evaluation['positive_event_refs'] = copy.deepcopy(req['positive_event_refs'])
    with pytest.raises(ValueError, match='overlap'):
        gen.generate(req, out / 'overlap-final', datasets, candidate=RULE, evaluation=evaluation)
    evaluation, sealed = evaluation_fixture(datasets)
    for e in sealed['sealed']['items']:
        del e['fields']['SourceImage']
    with pytest.raises(ValueError, match='copied development'):
        gen.generate(req, out / 'copied', datasets, candidate=RULE,
                     evaluation=evaluation, evaluation_datasets=sealed)
