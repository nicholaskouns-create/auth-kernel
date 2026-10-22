import copy
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from anticipatory import ProvenanceLedger, forecast, load_plan, manifest_digest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = dict(server='bank-adapter', tool='statement', endpoint='local-adapter',
                version='1', description='Read statement', input_schema={'type': 'object'})


class AnticipatoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'provenance.db'
        self.ledger = ProvenanceLedger(self.path)
        self.audiences = {'public': 'public', 'internal': 'restricted'}

    def check(self, artifact, content, audience='public', purpose='data'):
        return self.ledger.check(artifact, content, audience=audience,
                                 audiences=self.audiences, purpose=purpose)

    def test_transformed_sensitive_data_stays_sensitive_after_restart(self):
        self.ledger.register('secret', b'original', classification='restricted', trusted=True)
        self.ledger.derive('summary', b'summary', parents=['secret'])
        self.ledger.derive('translation', b'translation', parents=['summary'])
        self.ledger = ProvenanceLedger(self.path)
        self.assertFalse(self.check('translation', b'translation')['allowed'])
        self.assertTrue(self.check('translation', b'translation', 'internal')['allowed'])

    def test_mixed_ancestry_cannot_become_instructions(self):
        self.ledger.register('web', b'web', classification='public', trusted=False)
        self.ledger.register('host', b'host', classification='internal', trusted=True)
        self.ledger.derive('combined', b'combined', parents=['web', 'host'])
        self.assertTrue(self.check('combined', b'combined', 'internal')['allowed'])
        self.assertEqual(self.check('combined', b'combined', 'internal', 'instruction')['reason'],
                         'untrusted_instruction_ancestry')

    def test_content_substitution_and_unknowns_fail_closed(self):
        self.ledger.register('a', b'approved', classification='public', trusted=True)
        self.assertFalse(self.check('a', b'different')['allowed'])
        self.assertFalse(self.check('missing', b'approved')['allowed'])
        self.assertFalse(self.check('a', b'approved', 'unknown')['allowed'])

    def test_no_relabel_or_parent_omission(self):
        self.ledger.register('a', b'a', classification='restricted', trusted=False)
        for parents in ([], ['missing'], ['a', 'a']):
            with self.assertRaises(ValueError):
                self.ledger.derive('b', b'b', parents=parents)
        with self.assertRaises(ValueError):
            self.ledger.register('a', b'a', classification='public', trusted=True)
        self.assertFalse(self.check('a', b'a')['allowed'])

    def test_concurrent_artifact_registration_has_one_winner(self):
        def attempt(_):
            try:
                self.ledger.register('a', b'a', classification='public', trusted=False)
                return 1
            except ValueError:
                return 0
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(attempt, range(16))), 1)

    def test_tool_pin_covers_every_descriptor_field(self):
        self.ledger.pin('tool-v1', MANIFEST)
        self.assertTrue(self.ledger.check_tool('tool-v1', MANIFEST)['allowed'])
        for field, value in dict(server='other', tool='write', endpoint='other',
                                 version='2', description='Changed', input_schema={}).items():
            with self.subTest(field=field):
                self.assertFalse(self.ledger.check_tool('tool-v1', {**MANIFEST, field: value})['allowed'])
        self.assertFalse(self.ledger.check_tool('tool-v1', {**MANIFEST, 'extension': True})['allowed'])
        self.assertFalse(self.ledger.check_tool('unapproved', MANIFEST)['allowed'])
        with self.assertRaises(sqlite3.IntegrityError):
            self.ledger.pin('tool-v1', MANIFEST)

    def test_pin_canonical_order_and_invalid_manifest(self):
        self.assertEqual(manifest_digest(MANIFEST), manifest_digest(dict(reversed(list(MANIFEST.items())))))
        for manifest in ({}, {**MANIFEST, 'extra': float('nan')}):
            with self.assertRaises(ValueError):
                manifest_digest(manifest)

    def test_forecast_finds_compositions_and_preserves_input(self):
        plan = load_plan(ROOT / 'examples/anticipatory-plan.json')
        before = copy.deepcopy(plan)
        result = forecast(plan)
        self.assertEqual(result['paths_checked'], 6)
        self.assertEqual(result['status'], 'FINDINGS')
        self.assertEqual({f['reason'] for f in result['findings']},
                         {'classification_exceeds_clearance', 'untrusted_instruction_ancestry'})
        self.assertEqual(len(result['findings']), 2)
        self.assertEqual(plan, before)

    def test_truncation_never_reports_clean(self):
        plan = load_plan(ROOT / 'examples/anticipatory-plan.json')
        result = forecast(plan, max_paths=1)
        self.assertFalse(result['complete'])
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual(result['findings'], [])

    def test_forecast_tool_drift(self):
        plan = dict(sources=[], audiences={}, pins={'t': MANIFEST},
                    steps=[[dict(op='tool', id='t', manifest={**MANIFEST, 'version': '2'})]])
        self.assertEqual(forecast(plan)['status'], 'FINDINGS')
        plan['steps'][0][0]['manifest'] = MANIFEST
        self.assertEqual(forecast(plan)['status'], 'NO_FINDINGS_IN_MODEL')

    def test_cli_exit_codes_and_duplicate_json_keys(self):
        result = subprocess.run([sys.executable, 'anticipatory.py', 'examples/anticipatory-plan.json'],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['status'], 'FINDINGS')
        path = Path(self.tmp.name) / 'bad.json'
        path.write_text('{"sources": [], "sources": []}')
        with self.assertRaises(ValueError):
            load_plan(path)

    def test_unknown_labels_and_unexpected_events_fail(self):
        with self.assertRaises(ValueError):
            self.ledger.register('a', b'a', classification='guess', trusted=True)
        plan = dict(sources=[], audiences={}, pins={}, steps=[[{'op': 'execute'}]])
        with self.assertRaises(ValueError):
            forecast(plan)


if __name__ == '__main__':
    unittest.main()
