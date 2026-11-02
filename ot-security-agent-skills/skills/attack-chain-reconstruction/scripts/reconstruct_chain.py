#!/usr/bin/env python3
"""Offline, evidence-first attack timeline reconstruction (Python standard library)."""
import argparse
import csv
import datetime as dt
import hashlib
import json
import pathlib
import sys
from collections import Counter, defaultdict

STAGES = ('initial_access','execution','persistence','privilege_escalation','defense_evasion','credential_access','discovery','lateral_movement','collection','command_and_control','exfiltration','inhibit_response_function','impair_process_control','impact','other')
REQUIRED = ('timestamp','action','evidence')

def parse_time(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return dt.datetime.fromtimestamp(value, dt.timezone.utc)
    if not isinstance(value, str):
        raise ValueError('timestamp must be an ISO-8601 string or Unix epoch number')
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z','+00:00'))
    except ValueError as exc:
        raise ValueError(f'invalid timestamp: {value!r}') from exc
    if parsed.tzinfo is None:
        raise ValueError('timestamps must contain a timezone (e.g. Z or +03:00)')
    return parsed.astimezone(dt.timezone.utc)

def valid_event(ev, index, origin):
    if not isinstance(ev, dict):
        raise ValueError(f'{origin} event {index}: expected object')
    for key in REQUIRED:
        if key not in ev:
            raise ValueError(f'{origin} event {index}: missing {key}')
    if not isinstance(ev['action'], str) or not ev['action'].strip():
        raise ValueError(f'{origin} event {index}: action must be nonempty string')
    evidence = ev['evidence']
    if not isinstance(evidence, list) or not evidence or not all(isinstance(item, dict) and item.get('source') and (item.get('frame') is not None or item.get('line') is not None or item.get('record') is not None or item.get('detail')) for item in evidence):
        raise ValueError(f'{origin} event {index}: evidence requires nonempty list with source and frame/line/record/detail')
    time = parse_time(ev['timestamp'])
    stage = ev.get('stage', 'other')
    if stage not in STAGES:
        raise ValueError(f'{origin} event {index}: unknown stage {stage!r}')
    confidence = ev.get('confidence', 'observed')
    if confidence not in ('observed','inferred','hypothesis'):
        raise ValueError(f'{origin} event {index}: invalid confidence')
    # Inferences cannot be elevated to observed by the tool.
    output = dict(ev)
    output['timestamp'] = time.isoformat().replace('+00:00','Z')
    output['stage'] = stage
    output['confidence'] = confidence
    output.setdefault('id', f'{pathlib.Path(origin).stem}:{index}')
    output.setdefault('source_ip', None)
    output.setdefault('destination_ip', None)
    output.setdefault('protocol', None)
    return output

def load_events(paths):
    events = []
    inventory = []
    for p in paths:
        raw = p.read_bytes()
        doc = json.loads(raw.decode('utf-8-sig'))
        if isinstance(doc, list):
            rows = doc
        elif isinstance(doc, dict) and isinstance(doc.get('events'), list):
            rows = doc['events']
        else:
            raise ValueError(f'{p}: expected JSON list or object with events list')
        inventory.append({'path': str(p), 'sha256': hashlib.sha256(raw).hexdigest(), 'event_count': len(rows)})
        for i, row in enumerate(rows, 1):
            events.append(valid_event(row, i, str(p)))
    ids = [x['id'] for x in events]
    if len(set(ids)) != len(ids):
        raise ValueError('event ids must be globally unique; supply explicit ids to resolve collisions')
    return sorted(events, key=lambda x: (x['timestamp'], x['id'])), inventory

def reconstruct(events, inventory):
    by_id = {e['id']: e for e in events}
    links, warnings = [], []
    for event in events:
        for precursor in event.get('related_to', []):
            if precursor not in by_id:
                warnings.append(f"{event['id']}: related_to reference {precursor!r} not found")
                continue
            earlier = by_id[precursor]
            if earlier['timestamp'] > event['timestamp']:
                warnings.append(f"{event['id']}: related event {precursor} is later in time")
            links.append({'from': precursor, 'to': event['id'], 'type': 'analyst_asserted', 'confidence': event['confidence']})
    by_host = defaultdict(list)
    for event in events:
        for host in {event.get('source_ip'), event.get('destination_ip')} - {None, ''}:
            by_host[host].append(event['id'])
    return {
        'schema_version': '1.0',
        'summary': {'event_count': len(events), 'stages': dict(Counter(e['stage'] for e in events)), 'confidence': dict(Counter(e['confidence'] for e in events)), 'first_utc': events[0]['timestamp'] if events else None, 'last_utc': events[-1]['timestamp'] if events else None},
        'inputs': inventory,
        'events': events,
        'asserted_links': links,
        'host_event_index': dict(sorted(by_host.items())),
        'warnings': warnings,
        'limitations': ['Chronological adjacency does not prove causality.', 'Related_to links are supplied by analysts, not automatically established.', 'Observed packets/commands do not by themselves prove successful exploitation or physical impact.', 'No network traffic is generated and no live assets are contacted.']
    }

def to_markdown(result):
    lines = ['# Attack-chain evidence timeline','',f"Events: {result['summary']['event_count']} | Asserted links: {len(result['asserted_links'])}",'', '| UTC timestamp | Stage | Action | Source → Destination | Evidence | Confidence |','|---|---|---|---|---|---|']
    for e in result['events']:
        evidence = '; '.join(f"{x['source']}:{x.get('frame', x.get('line', x.get('record', x.get('detail', '?'))))}" for x in e['evidence'])
        cells = [e['timestamp'],e['stage'],e['action'],f"{e.get('source_ip') or '?'} → {e.get('destination_ip') or '?'}",evidence,e['confidence']]
        lines.append('| '+' | '.join(str(c).replace('|', r'\|').replace('\n', ' ') for c in cells)+' |')
    lines += ['', '## Caveats', ''] + [f'- {s}' for s in result['limitations']]
    if result['warnings']:
        lines += ['', '## Warnings', ''] + [f'- {s}' for s in result['warnings']]
    return '\n'.join(lines)+'\n'

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('inputs', nargs='+', type=pathlib.Path, help='JSON evidence event files')
    ap.add_argument('--output', '-o', type=pathlib.Path, help='JSON report output (stdout by default)')
    ap.add_argument('--markdown', type=pathlib.Path, help='Optional Markdown timeline')
    args = ap.parse_args(argv)
    try:
        events, inventory = load_events(args.inputs)
        result = reconstruct(events, inventory)
        rendered = json.dumps(result, ensure_ascii=False, indent=2)+'\n'
        if args.output:
            args.output.write_text(rendered, encoding='utf-8')
        else:
            print(rendered, end='')
        if args.markdown:
            args.markdown.write_text(to_markdown(result), encoding='utf-8')
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
