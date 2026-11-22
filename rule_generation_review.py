"""Evidence attribution, condition diagnostics, and isolated final evaluation."""
from __future__ import annotations

import hashlib
import json

from run_sigma_offline import field_matches, selector_matches
from validate_contract import EVENT_REF
from jsonschema import validate


def evidence_catalog(request):
    items = request.get('evidence_items', [])
    ids = [item['evidence_id'] for item in items]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate evidence ID')
    allowed = {'report_fact', 'manual_goal', 'constraint', 'assumption'}
    for item in items:
        if item.get('kind') not in allowed or not isinstance(item.get('text'), str) or not item['text']:
            raise ValueError('Evidence needs a kind and nonempty text')
        if item['kind'] == 'assumption' and item['evidence_id'] not in request.get('allowed_assumption_ids', []):
            raise ValueError('Assumption is not explicitly allowed')
    return {item['evidence_id']: item for item in items}


def condition_diagnostics(rule, event):
    result = []
    for name, selector in rule['detection'].items():
        if name == 'condition':
            continue
        branches = selector if isinstance(selector, list) else [selector]
        for index, branch in enumerate(branches):
            for key, value in branch.items():
                field, *mods = key.split('|')
                present = field in event['fields']
                result.append({'selector': name, 'branch_index': index, 'field': field,
                               'modifier': '|'.join(mods) or 'equals',
                               'status': 'missing' if not present else
                               'match' if field_matches(event['fields'][field], value, mods) else 'no_match',
                               'selector_matches': selector_matches(selector, event['fields'])})
    return result


def diagnostic_feedback(test):
    """Only condition outcomes enter revision; actual event values/UIDs stay private."""
    return '; '.join(f"{c['selector']}.{c['field']}={c['status']}" for c in test.get('condition_diagnostics', []))


def sample_outcome(positive, negative, label):
    if any(t['status'] == 'miss' for t in positive) or any(t['status'] == 'hit' for t in negative):
        return 'failed'
    if not positive or not negative or any(t['status'] not in ('hit', 'miss') for t in positive + negative):
        return 'incomplete'
    return label


def validate_split(request, evaluation, datasets, evaluation_datasets):
    if evaluation is None:
        return
    if evaluation.get('independence') not in ('synthetic_boundary', 'same_source_holdout', 'independent_source'):
        raise ValueError('Evaluation must declare independence scope')
    dev = request['positive_event_refs'] + request['negative_event_refs']
    positive = evaluation.get('positive_event_refs', [])
    negative = evaluation.get('negative_event_refs', [])
    refs = positive + negative
    for ref in refs:
        validate(ref, EVENT_REF)
    keys = lambda rs: {(r['dataset_id'], r['event_uid']) for r in rs}
    if keys(dev) & keys(refs) or keys(positive) & keys(negative):
        raise ValueError('Development/evaluation or evaluation positive/negative overlap')
    if evaluation['independence'] == 'synthetic_boundary' and any(r['provenance'] != 'synthetic' for r in refs):
        raise ValueError('Synthetic boundary evaluation must use synthetic provenance')
    def fingerprints(refs, data):
        result = set()
        for ref in refs:
            ds = data.get(ref['dataset_id'], {})
            for event in ds.get('items', []):
                if event['event_uid'] == ref['event_uid']:
                    payload = {k: event.get(k) for k in ('event_code', 'channel', 'timestamp_raw', 'fields')}
                    result.add(hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest())
        return result
    if fingerprints(dev, datasets) & fingerprints(refs, evaluation_datasets):
        raise ValueError('Evaluation contains copied development events under different IDs')
    if evaluation['independence'] == 'independent_source':
        if any(r['provenance'] == 'synthetic' for r in refs):
            raise ValueError('Synthetic samples are not independent-source logs')
        sources = lambda rs, data: {data[r['dataset_id']].get('source_path') for r in rs if r['dataset_id'] in data}
        if sources(dev, datasets) & sources(refs, evaluation_datasets):
            raise ValueError('Independent-source evaluation cannot share development source paths')
