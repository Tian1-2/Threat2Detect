import copy
import hashlib
import json
from pathlib import Path

import pytest

from src.threat2detect.pipeline import controller as mod


@pytest.fixture
def setup(tmp_path, monkeypatch):
    handoff = json.loads((mod.ROOT / 'data/annotations/aa25_266a_gold_draft.json').read_text())
    handoff['behaviors'] = handoff['behaviors'][:1]
    bid = handoff['behaviors'][0]['behavior_id']
    handoff['mappings'] = [m for m in handoff['mappings'] if m['behavior_id'] == bid]
    handoff['telemetry'] = []
    candidates = json.loads((mod.ROOT / 'data/annotations/aa25_266a_rule_candidates.json').read_text())
    candidate = copy.deepcopy(next(c for c in candidates['items'] if c['behavior_id'] == bid))
    candidate['required_fields'] = ['Image']
    monkeypatch.setattr(mod, 'relative', lambda p: str(p))
    monkeypatch.setattr(mod, 'retrieve', lambda *a, **kw: {
        'schema_version': '1.0', 'kind': 'rule_candidates', 'case_id': handoff['case_id'],
        'ruleset_commit': candidates['ruleset_commit'], 'items': [copy.deepcopy(candidate)]})
    events = {'schema_version': '1.0', 'kind': 'normalized_events', 'dataset_id': 'test',
              'source_path': 'synthetic:test', 'parse_error_count': 0, 'items': [
                  {'event_uid': 'test:1', 'event_code': 1, 'channel': 'Microsoft-Windows-Sysmon/Operational',
                   'host': 'synthetic', 'timestamp_raw': None, 'raw_ref': 'synthetic:test:1',
                   'fields': {'Image': r'C:\Windows\System32\whoami.exe'}}]}
    return handoff, candidate, events, tmp_path


def test_offline_policy_executes_and_keeps_procedure_unknown(setup):
    handoff, candidate, events, out = setup
    agent = mod.CaseController(out / 'offline', handoff=handoff, events=events,
                               controller='policy', skip_coverage=True)
    result = agent.run()
    assert result['workflow_status'] == 'completed_with_review'
    assert result['model_calls_used'] == 0
    assert result['items'][0]['procedure_decision'] is None
    assert result['items'][0]['sample_test_status'] == 'hit'
    assert result['review_queue']
    trace = [json.loads(x) for x in (out / 'offline/trace.jsonl').read_text().splitlines()]
    assert [x['action']['tool'] for x in trace] == [
        'read_context', 'search_rules', 'check_telemetry', 'test_rule', 'request_review', 'finish']


def test_unknown_behavior_stops_for_review_without_retrieval(setup):
    handoff, _, events, out = setup
    handoff['behaviors'][0]['fact_status'] = 'unclear'
    agent = mod.CaseController(out / 'unclear', handoff=handoff, events=events, controller='policy')
    result = agent.run()
    assert not result['items']
    assert 'unclear' in result['review_queue'][0]['reason']


def test_missing_telemetry_does_not_become_miss(setup):
    handoff, _, _, out = setup
    result = mod.CaseController(out / 'none', handoff=handoff, controller='policy', skip_coverage=True).run()
    assert result['items'][0]['sample_test_status'] is None
    assert result['items'][0]['telemetry']['executable'] is False


def test_step_and_model_budgets_preserve_partial_results(setup):
    handoff, _, events, out = setup
    result = mod.CaseController(out / 'steps', handoff=handoff, events=events, controller='policy',
                                limits=mod.Limits(steps=1), skip_coverage=True).run()
    assert result['workflow_status'] == 'budget_exhausted'
    assert result['pending_behavior_ids']
    def llm(model, system, user, endpoint, schema):
        return {'action_id': next(iter(schema['properties']['action_id']['enum'])), 'reason': 'Inspect next item'}
    result = mod.CaseController(out / 'calls', handoff=handoff, events=events, llm=llm,
                                limits=mod.Limits(model_calls=1)).run()
    assert result['workflow_status'] == 'budget_exhausted'
    assert result['model_calls_used'] == 1


def test_invalid_model_actions_never_dispatch(setup):
    handoff, _, _, out = setup
    result = mod.CaseController(out / 'bad', handoff=handoff,
        llm=lambda *_: {'action_id': 'finish', 'reason': 'Skip evidence'}).run()
    assert result['workflow_status'] == 'controller_error'
    assert result['model_calls_used'] == 2
    assert not result['items']


def test_empty_search_is_not_a_generation_gap(setup, monkeypatch):
    handoff, _, _, out = setup
    monkeypatch.setattr(mod, 'retrieve', lambda *a, **kw: {'schema_version': '1.0', 'kind': 'rule_candidates',
        'case_id': handoff['case_id'], 'ruleset_commit': '0' * 40, 'items': []})
    plan = [{'behavior_id': handoff['behaviors'][0]['behavior_id'], 'trigger': 'coverage_gap',
             'request_path': 'data/annotations/rule_generation_request_example.json'}]
    result = mod.CaseController(out / 'empty', handoff=handoff, controller='policy',
        enable_generation=True, generation_plan=plan).run()
    assert not result['generated_rules']
    assert 'not proof' in result['review_queue'][0]['reason']
    assert 'gate was not satisfied' in result['review_queue'][0]['reason']


def test_generation_is_opt_in_and_guarded(setup):
    handoff, _, _, out = setup
    plan = [{'behavior_id': handoff['behaviors'][0]['behavior_id'], 'trigger': 'explicit_request',
             'request_path': 'data/annotations/rule_generation_request_example.json'}]
    with pytest.raises(ValueError, match='enable-generation'):
        mod.CaseController(out / 'disabled', handoff=handoff, generation_plan=plan)
    generated = []
    def stub(agent, action):
        generated.append(action['trigger'])
        agent.generated[action['behavior_id']] = {'review_status': 'draft', 'note': 'Manual request'}
        return {'parse_status': 'valid'}
    agent = mod.CaseController(out / 'enabled', handoff=handoff, controller='policy', skip_coverage=True,
        enable_generation=True, generation_plan=plan, tools={'generate_rule': stub})
    result = agent.run()
    assert generated == ['explicit_request']
    assert result['generated_rules']


def test_tool_error_is_recorded_and_not_repeated(setup):
    handoff, _, _, out = setup
    calls = []
    def broken(*_):
        calls.append(1)
        raise RuntimeError('retrieval failed')
    result = mod.CaseController(out / 'error', handoff=handoff, controller='policy',
        tools={'search_rules': broken}).run()
    assert len(calls) == 1
    assert 'retrieval failed' in result['review_queue'][0]['reason']
    assert (out / 'error/state.json').exists()


def test_specialist_calls_share_controller_budget(setup, monkeypatch):
    handoff, _, _, out = setup
    def specialist(item, model, endpoint, max_steps, llm):
        for _ in range(2):
            llm(model, 'specialist', '{}', endpoint, {})
        raise AssertionError('second call should exceed budget')
    monkeypatch.setattr(mod, 'analyze_candidate', specialist)
    agent = mod.CaseController(out / 'shared', handoff=handoff, controller='policy',
        limits=mod.Limits(model_calls=1), llm=lambda *_: {})
    result = agent.run()
    assert result['workflow_status'] == 'budget_exhausted'
    assert result['model_calls_used'] == 1


def test_draft_behavior_not_promoted_by_confirmed_mapping(setup):
    handoff, _, _, out = setup
    handoff['behaviors'][0]['review_status'] = 'draft'
    result = mod.CaseController(out / 'draft', handoff=handoff, controller='policy').run()
    assert not result['items']
    assert handoff['behaviors'][0]['review_status'] == 'draft'


@pytest.mark.parametrize('decision,expected', [('does_not_match', True), ('insufficient_detail', False)])
def test_gap_generation_requires_all_retrieved_candidates_rejected(setup, decision, expected):
    handoff, _, _, out = setup
    bid = handoff['behaviors'][0]['behavior_id']
    def assess(agent, action):
        cid = action['candidate_id']
        agent.coverage[cid] = {'coverage_id': cid + '-C', 'candidate_id': cid,
            'behavior_id': bid, 'decision': decision, 'supporting_conditions': [],
            'missing_conditions': [], 'unknown_conditions': [], 'explanation': 'Test judgment', 'review_status': 'draft'}
        return agent.coverage[cid]
    def generate(agent, action):
        agent.generated[bid] = {'review_status': 'draft'}
        return agent.generated[bid]
    plan = [{'behavior_id': bid, 'trigger': 'coverage_gap',
             'request_path': 'data/annotations/rule_generation_request_example.json'}]
    result = mod.CaseController(out / decision, handoff=handoff, controller='policy',
        enable_generation=True, generation_plan=plan,
        tools={'assess_candidate': assess, 'generate_rule': generate}).run()
    assert bool(result['generated_rules']) == expected


def test_time_budget_stops_before_next_tool(setup):
    handoff, _, _, out = setup
    agent = mod.CaseController(out / 'time', handoff=handoff, controller='policy')
    agent.started -= agent.limits.seconds + 1
    result = agent.run()
    assert result['workflow_status'] == 'budget_exhausted'
    assert result['steps_used'] == 0


def test_behavior_limit_reports_omitted_work(setup):
    handoff, _, _, out = setup
    other = copy.deepcopy(handoff['behaviors'][0]);other['behavior_id'] = 'AA25-266A-OTHER'
    handoff['behaviors'].append(other)
    result = mod.CaseController(out / 'partial', handoff=handoff, controller='policy',
        skip_coverage=True, limits=mod.Limits(behaviors=1)).run()
    assert result['workflow_status'] == 'partial_with_review'
    assert result['unselected_behavior_ids'] == ['AA25-266A-OTHER']


def test_generated_tool_propagates_shared_budget_exhaustion(setup, monkeypatch):
    import generate_rule
    handoff, _, _, out = setup
    monkeypatch.setattr(generate_rule, 'ROOT', out)
    bid = handoff['behaviors'][0]['behavior_id']
    handoff['behaviors'][0]['review_status'] = 'draft'
    plan = [{'behavior_id': bid, 'trigger': 'explicit_request',
             'request_path': 'data/annotations/rule_generation_request_example.json'}]
    # First malformed model response uses the only call. Revision must not swallow budget exhaustion.
    result = mod.CaseController(out / 'generation-budget', handoff=handoff, controller='policy',
        enable_generation=True, generation_plan=plan, limits=mod.Limits(model_calls=1),
        llm=lambda *_: {}).run()
    assert result['workflow_status'] == 'budget_exhausted'
    assert result['model_calls_used'] == 1
    assert not result['generated_rules']
