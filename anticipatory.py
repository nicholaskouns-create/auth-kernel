"""White Hats anticipatory instruments: local, deterministic, standard-library only.

Host-owned provenance and policy; agent output is never an authority source.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import itertools
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

LEVELS = {'public': 0, 'internal': 1, 'confidential': 2, 'restricted': 3}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def identifier(value):
    if type(value) is not str or not value or len(value) > 256:
        raise ValueError('invalid identifier')
    return value


def level(value):
    if type(value) is not str or value not in LEVELS:
        raise ValueError('unknown classification')
    return LEVELS[value]


def manifest_digest(manifest):
    """Pin full JSON descriptor, including unknown extension fields."""
    if type(manifest) is not dict:
        raise ValueError('manifest must be an object')
    for key in ('server', 'tool', 'endpoint', 'version'):
        identifier(manifest.get(key))
    if type(manifest.get('description')) is not str or type(manifest.get('input_schema')) is not dict:
        raise ValueError('description and input_schema are required')
    return digest(manifest)


def source(state, artifact, classification, trusted):
    identifier(artifact)
    level(classification)
    if type(trusted) is not bool or artifact in state:
        raise ValueError('source must be new and have explicit boolean trust')
    state[artifact] = {'classification': classification, 'trusted': trusted, 'parents': []}


def derive(state, artifact, parents):
    identifier(artifact)
    if artifact in state or type(parents) is not list or not parents or len(parents) != len(set(parents)):
        raise ValueError('new artifact and unique nonempty parent list required')
    for parent in parents:
        identifier(parent)
        if parent not in state:
            raise ValueError('unknown parent')
    classification = max((state[p]['classification'] for p in parents), key=level)
    state[artifact] = {'classification': classification,
                       'trusted': all(state[p]['trusted'] for p in parents),
                       'parents': sorted(parents)}


def assess(state, artifact, audience, audiences, *, purpose='data'):
    """Decision only. Host must bind this check to the exact bytes sent."""
    if purpose not in ('data', 'instruction'):
        raise ValueError('unknown purpose')
    if artifact not in state:
        return {'allowed': False, 'reason': 'unknown_artifact'}
    if audience not in audiences:
        return {'allowed': False, 'reason': 'unknown_audience'}
    clearance = level(audiences[audience])
    entry = state[artifact]
    if level(entry['classification']) > clearance:
        return {'allowed': False, 'reason': 'classification_exceeds_clearance'}
    if purpose == 'instruction' and not entry['trusted']:
        return {'allowed': False, 'reason': 'untrusted_instruction_ancestry'}
    return {'allowed': True, 'reason': 'allow'}


class ProvenanceLedger:
    """Durable host instrument. APIs and SQLite file must be inaccessible to agents.

    Immutable artifact IDs bind SHA-256 of exact bytes, labels and parent edges.
    Derived content inherits maximum sensitivity and the conjunction of trust.
    """
    def __init__(self, path):
        self.path = str(path)
        if self.path == ':memory:':
            raise ValueError('persistent database required')
        with self.connection() as db:
            db.execute('CREATE TABLE IF NOT EXISTS artifacts(id TEXT PRIMARY KEY, body TEXT NOT NULL, content_hash TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS tools(id TEXT PRIMARY KEY, digest TEXT NOT NULL)')

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def content_hash(content):
        if type(content) is not bytes:
            raise ValueError('content must be exact bytes')
        return hashlib.sha256(content).hexdigest()

    @staticmethod
    def _state(db):
        return {row[0]: json.loads(row[1]) for row in db.execute('SELECT id,body FROM artifacts')}

    def register(self, artifact, content, *, classification, trusted):
        content_hash = self.content_hash(content)
        with self.connection() as db:
            state = self._state(db)
            source(state, artifact, classification, trusted)
            db.execute('INSERT INTO artifacts VALUES(?,?,?)',
                       (artifact, canonical(state[artifact]), content_hash))

    def derive(self, artifact, content, *, parents):
        content_hash = self.content_hash(content)
        with self.connection() as db:
            state = self._state(db)
            derive(state, artifact, parents)
            db.execute('INSERT INTO artifacts VALUES(?,?,?)',
                       (artifact, canonical(state[artifact]), content_hash))

    def check(self, artifact, content, *, audience, audiences, purpose='data'):
        content_hash = self.content_hash(content)
        with self.connection() as db:
            row = db.execute('SELECT content_hash FROM artifacts WHERE id=?', (artifact,)).fetchone()
            if row is None or row[0] != content_hash:
                return {'allowed': False, 'reason': 'unregistered_or_changed_content'}
            return assess(self._state(db), artifact, audience, audiences, purpose=purpose)

    def pin(self, tool_id, manifest):
        """Explicit trusted installation, never automatic trust-on-first-use."""
        identifier(tool_id)
        value = manifest_digest(manifest)
        with self.connection() as db:
            # Re-pinning an existing ID fails. Version changes need a new approved ID.
            db.execute('INSERT INTO tools VALUES(?,?)', (tool_id, value))
        return value

    def check_tool(self, tool_id, manifest):
        actual = manifest_digest(manifest)
        with self.connection() as db:
            row = db.execute('SELECT digest FROM tools WHERE id=?', (tool_id,)).fetchone()
        return {'allowed': row is not None and row[0] == actual,
                'reason': 'unknown_tool' if row is None else 'allow' if row[0] == actual else 'tool_definition_changed',
                'observed_digest': actual}


def forecast(plan, max_paths=256):
    """Enumerate bounded combinations of declared step alternatives, with no I/O.

    Findings are reachable denied actions in the supplied model, not predictions
    of real incidents. Truncation always produces INCOMPLETE, never a clean result.
    """
    if type(max_paths) is not int or not 1 <= max_paths <= 4096:
        raise ValueError('max_paths must be between 1 and 4096')
    if type(plan) is not dict or set(plan) != {'sources', 'audiences', 'pins', 'steps'}:
        raise ValueError('plan requires sources, audiences, pins, steps only')
    if type(plan['sources']) is not list or type(plan['steps']) is not list or len(plan['steps']) > 64:
        raise ValueError('invalid sources/steps or more than 64 steps')
    if type(plan['audiences']) is not dict or type(plan['pins']) is not dict:
        raise ValueError('audiences and pins must be mappings')
    for audience, clearance in plan['audiences'].items():
        identifier(audience)
        level(clearance)
    pins = {identifier(k): manifest_digest(v) for k, v in plan['pins'].items()}
    initial = {}
    for entry in plan['sources']:
        if type(entry) is not dict or set(entry) != {'id', 'classification', 'trusted'}:
            raise ValueError('invalid source')
        source(initial, entry['id'], entry['classification'], entry['trusted'])
    total = 1
    for options in plan['steps']:
        if type(options) is not list or not options or len(options) > 64:
            raise ValueError('each step needs 1..64 alternatives')
        total *= len(options)
    findings = []
    checked = 0
    for choices in itertools.islice(itertools.product(*plan['steps']), max_paths):
        state = copy.deepcopy(initial)
        checked += 1
        for step, event in enumerate(choices):
            if type(event) is not dict:
                raise ValueError('event must be an object')
            op = event.get('op')
            if op == 'derive' and set(event) == {'op', 'id', 'parents'}:
                derive(state, event['id'], event['parents'])
                continue
            if op == 'export' and set(event) == {'op', 'id', 'audience', 'purpose'}:
                decision = assess(state, event['id'], event['audience'], plan['audiences'], purpose=event['purpose'])
            elif op == 'tool' and set(event) == {'op', 'id', 'manifest'}:
                actual = manifest_digest(event['manifest'])
                decision = {'allowed': event['id'] in pins and pins[event['id']] == actual,
                            'reason': 'tool_definition_changed_or_unpinned'}
            else:
                raise ValueError('unknown operation or unexpected fields')
            if not decision['allowed']:
                findings.append({'path': checked, 'step': step, 'reason': decision['reason'],
                                 'trace': list(choices[:step + 1])})
                # Host stops this path at its first denied action.
                break
    complete = checked == total
    return {'schema_version': 1, 'status': 'INCOMPLETE' if not complete else 'FINDINGS' if findings else 'NO_FINDINGS_IN_MODEL',
            'complete': complete, 'paths_checked': checked, 'paths_declared': total,
            'findings': findings}


def load_plan(path):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    data = Path(path).read_bytes()
    if len(data) > 1_000_000:
        raise ValueError('plan exceeds 1 MB')
    return json.loads(data, object_pairs_hook=unique_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('non-finite JSON')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('plan', help='local JSON workflow model')
    parser.add_argument('--max-paths', type=int, default=256)
    args = parser.parse_args()
    try:
        result = forecast(load_plan(args.plan), args.max_paths)
    except (ValueError, TypeError, KeyError, OSError, RecursionError) as error:
        print(json.dumps({'status': 'INVALID_MODEL', 'error': str(error)}))
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'NO_FINDINGS_IN_MODEL' else 1


if __name__ == '__main__':
    raise SystemExit(main())
