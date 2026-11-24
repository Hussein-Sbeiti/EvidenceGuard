import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.ai import LocalAI
from app.training_data import (DEFAULT_DATASET, describe, doctor, explanation_example,
                               fingerprint, prepare, record_digest, sha256, split_for, validate_dataset,
                               apply_reviews, review_packet)


class TrainingDataTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.data = json.loads(DEFAULT_DATASET.read_text())
        self.path = self.root / 'dataset.json'

    def save(self):
        self.path.write_text(json.dumps(self.data))
        return self.path

    def approve(self):
        # Synthetic approvals are confined to temporary test data, never the pilot.
        for record in self.data['records']:
            for state in ('review', 'screening'):
                record[state] = {'status': 'approved', 'reviewer': 'test-reviewer', 'date': '2026-11-23',
                                 'rationale': 'Synthetic approval for export tests only.',
                                 'record_sha256': record_digest(record)}

    def test_pilot_is_valid_draft_and_includes_safe_and_unknown_cases(self):
        summary = describe(validate_dataset())
        self.assertEqual(summary['records'], 18)
        self.assertEqual(summary['families'], 10)
        self.assertEqual(summary['review_statuses'], {'pending': 18})
        self.assertEqual(summary['labels'], {'vulnerable': 8, 'safe': 8, 'insufficient_context': 2})

    def test_pending_and_rejected_records_cannot_export_or_create_directory(self):
        for status in ('pending', 'rejected'):
            with self.subTest(status=status):
                self.approve()
                self.data['records'][0]['screening']['status'] = status
                output = self.root / status
                with self.assertRaisesRegex(ValueError, 'All records'):
                    prepare(self.save(), output)
                self.assertFalse(output.exists())

    def test_export_is_reproducible_grouped_and_excludes_test_answers(self):
        self.approve()
        path = self.save()
        one = prepare(path, self.root / 'one')
        two = prepare(path, self.root / 'two')
        self.assertEqual(one, two)
        self.assertEqual(one['dataset_sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(set(one['implementation_sha256']), {'training_data.py', 'ai.py', 'scanner.py', 'sql_analysis.py'})
        self.assertEqual(set(one['splits']), {'train', 'validation', 'test'})
        self.assertEqual(sum(map(len, one['splits'].values())), len(self.data['records']))
        for record in self.data['records']:
            self.assertIn(record['id'], one['splits'][split_for(record['family'])])
        self.assertEqual(set(p.name for p in (self.root / 'one').iterdir()),
                         {'manifest.json', 'explanation.train.jsonl', 'explanation.validation.jsonl'})
        for name, digest in one['file_sha256'].items():
            self.assertEqual(hashlib.sha256((self.root / 'one' / name).read_bytes()).hexdigest(), digest)
        with self.assertRaises(FileExistsError):
            prepare(path, self.root / 'one')

    def test_runtime_prompt_and_output_contract_match_real_client(self):
        record = self.data['records'][0]
        example = explanation_example(record)
        captured = []
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size):
                return json.dumps({'done': True, 'model': 'test-model',
                                   'message': {'content': example['completion'][0]['content']}}).encode()
        def opener(request, timeout):
            captured.append(json.loads(request.data))
            return Response()
        from app.scanner import scan_source
        ai = LocalAI(model='test-model', opener=opener)
        result = ai.explain(scan_source('pilot.py', record['source']), enabled=True)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(captured[0]['messages'], example['prompt'])
        self.assertEqual(result['explanations'][0]['remediation'], record['explanation_target']['remediation'])
        self.assertNotIn(record['source'], example['prompt'][1]['content'])

    def test_every_vulnerable_pilot_target_has_a_matching_finding(self):
        for record in self.data['records']:
            if record['label'] == 'vulnerable':
                with self.subTest(record=record['id']):
                    example = explanation_example(record)
                    self.assertEqual(json.loads(example['completion'][0]['content'])['explanations'][0]['id'], 0)

    def test_stale_approvals_and_self_approval_are_rejected(self):
        self.approve()
        self.data['records'][0]['remediation'] += ' Changed.'
        with self.assertRaisesRegex(ValueError, 'stale'):
            validate_dataset(self.save())
        self.approve()
        self.data['records'][0]['review']['reviewer'] = self.data['records'][0]['author']
        with self.assertRaisesRegex(ValueError, 'other than the author'):
            validate_dataset(self.save())

    def test_changed_source_hash_and_invalid_fix_are_rejected(self):
        self.data['records'][0]['source'] += '\n'
        with self.assertRaisesRegex(ValueError, 'sha256 mismatch'):
            validate_dataset(self.save())
        self.data['records'][0]['source_sha256'] = sha256(self.data['records'][0]['source'])
        self.data['records'][0]['fixed_source'] = 'def invalid('
        with self.assertRaisesRegex(ValueError, 'invalid Python'):
            validate_dataset(self.save())

    def test_development_fixture_cannot_be_reused_even_with_comment_or_rename(self):
        record = self.data['records'][0]
        record['source'] = '# reworded comment\nrenamed = eval(other_name)\n'
        record['source_sha256'] = sha256(record['source'])
        with self.assertRaisesRegex(ValueError, 'evaluation corpus'):
            validate_dataset(self.save())

    def test_fix_cannot_leak_from_development_corpus(self):
        self.data['records'][0]['fixed_source'] = 'another = json.loads(other)\n'
        with self.assertRaisesRegex(ValueError, 'evaluation corpus'):
            validate_dataset(self.save())

    def test_renamed_clone_cannot_cross_families(self):
        record = copy.deepcopy(self.data['records'][0])
        record.update(id='clone', family='unrelated', source=record['source'].replace('cursor', 'db'))
        record['source_sha256'] = sha256(record['source'])
        self.data['records'].append(record)
        with self.assertRaisesRegex(ValueError, 'structural duplicate'):
            validate_dataset(self.save())

    def test_fixed_variant_cannot_move_to_a_different_family(self):
        self.data['records'][1]['family'] = 'unrelated'
        with self.assertRaisesRegex(ValueError, 'structural duplicate'):
            validate_dataset(self.save())

    def test_ast_normalization_does_not_execute_source(self):
        self.assertEqual(fingerprint('raise RuntimeError("never execute")\n'),
                         fingerprint('# ignored\nraise RuntimeError("never execute")\n'))
        self.assertEqual(fingerprint('value = input_name\n'), fingerprint('renamed = changed\n'))

    def test_split_is_stable_when_more_families_are_added(self):
        before = {r['family']: split_for(r['family']) for r in self.data['records']}
        split_for('new-family')
        self.assertEqual(before, {family: split_for(family) for family in before})
        self.assertEqual(before['search_prefix'], 'validation')

    def test_malformed_metadata_labels_and_evidence_are_rejected(self):
        for field, value in [('evidence_lines', [True]), ('label', 'secure'), ('provenance', {}),
                             ('review', {}), ('explanation_target', {})]:
            with self.subTest(field=field):
                data = copy.deepcopy(self.data)
                self.data['records'][0][field] = value
                with self.assertRaises(ValueError):
                    validate_dataset(self.save())
                self.data = data

    def test_doctor_only_reports_inventory(self):
        result = doctor()
        self.assertFalse(result['training_performed'])
        self.assertIn('torch', result['packages_in_this_interpreter'])
        self.assertIn('/dev/kfd', result['device_nodes_visible'])

    def test_identical_bounded_prompts_cannot_cross_splits(self):
        self.approve()
        example = explanation_example(self.data['records'][0])
        with patch('app.training_data.explanation_example', return_value=example):
            with self.assertRaisesRegex(ValueError, 'Identical bounded prompts'):
                prepare(self.save(), self.root / 'bad-export')
        self.assertFalse((self.root / 'bad-export').exists())

    def packet(self):
        path = self.root / 'packet.json'
        review_packet(self.save(), path)
        return path, json.loads(path.read_text())

    def test_review_packet_includes_full_record_hash_target_and_diagnostics_without_approving(self):
        path, packet = self.packet()
        self.assertEqual(len(packet['records']), 18)
        item = packet['records'][0]
        self.assertEqual(item['record_sha256'], record_digest(self.data['records'][0]))
        self.assertEqual(item['bounded_example'], explanation_example(self.data['records'][0]))
        self.assertEqual(item['decisions']['review']['status'], 'pending')
        self.assertIn('scanner_observation', item)
        self.assertEqual(json.loads(self.path.read_text()), self.data)
        if os.name != 'nt':
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            review_packet(self.path, path)

    def decision(self):
        return {'status': 'approved', 'reviewer': 'worksheet-test-reviewer', 'date': '2026-11-23',
                'rationale': 'Synthetic test review; not a real approval.'}

    def test_completed_worksheet_import_preserves_original_and_binds_new_dataset_approvals(self):
        path, packet = self.packet()
        for item in packet['records']:
            item['decisions'] = {kind: self.decision() for kind in ('review', 'screening')}
        path.write_text(json.dumps(packet))
        output = self.root / 'reviewed.json'
        original = self.path.read_bytes()
        result = apply_reviews(self.path, path, output, 'reviewed-test-1')
        self.assertEqual(result['decisions_imported'], 36)
        self.assertEqual(self.path.read_bytes(), original)
        data = validate_dataset(output)
        self.assertEqual(data['version'], 'reviewed-test-1')
        self.assertTrue(all(r['review']['status'] == 'approved' for r in data['records']))
        prepare(output, self.root / 'reviewed-export')
        with self.assertRaises(FileExistsError):
            apply_reviews(self.path, path, output, 'reviewed-test-1')

    def test_empty_worksheet_does_not_create_an_approved_dataset(self):
        path, _ = self.packet()
        output = self.root / 'not-reviewed.json'
        with self.assertRaisesRegex(ValueError, 'No completed'):
            apply_reviews(self.path, path, output, 'reviewed-test-1')
        self.assertFalse(output.exists())

    def test_partial_review_remains_untrainable(self):
        path, packet = self.packet()
        packet['records'][0]['decisions']['review'] = self.decision()
        path.write_text(json.dumps(packet))
        output = self.root / 'partial.json'
        apply_reviews(self.path, path, output, 'partial-test-1')
        self.assertEqual(describe(validate_dataset(output))['review_statuses'], {'approved': 1, 'pending': 17})
        with self.assertRaisesRegex(ValueError, 'All records'):
            prepare(output, self.root / 'partial-export')

    def test_changed_dataset_cannot_receive_old_worksheet_decisions(self):
        path, _ = self.packet()
        self.data['records'][0]['rationale'] += ' Revised.'
        self.save()
        with self.assertRaisesRegex(ValueError, 'stale'):
            apply_reviews(self.path, path, self.root / 'bad.json', 'reviewed-test-1')

    def test_modified_worksheet_source_or_prompt_is_rejected(self):
        path, packet = self.packet()
        original = copy.deepcopy(packet)
        for field in ('record', 'bounded_example'):
            with self.subTest(field=field):
                packet = copy.deepcopy(original)
                if field == 'record':
                    packet['records'][0]['record']['rationale'] = 'Changed in worksheet.'
                else:
                    packet['records'][0]['bounded_example']['completion'][0]['content'] = '{}'
                path.write_text(json.dumps(packet))
                with self.assertRaisesRegex(ValueError, 'changed'):
                    apply_reviews(self.path, path, self.root / 'bad.json', 'reviewed-test-1')

    def test_worksheet_cannot_self_approve_or_omit_decision_metadata(self):
        path, packet = self.packet()
        original = copy.deepcopy(packet)
        for field, value in (('reviewer', 'codex-author'), ('rationale', ''), ('date', 'not-a-date')):
            with self.subTest(field=field):
                packet = copy.deepcopy(original)
                packet['records'][0]['decisions']['review'] = {**self.decision(), field: value}
                path.write_text(json.dumps(packet))
                with self.assertRaises(ValueError):
                    apply_reviews(self.path, path, self.root / 'bad.json', 'reviewed-test-1')

    def test_duplicate_worksheet_records_are_rejected(self):
        path, packet = self.packet()
        packet['records'][1] = packet['records'][0]
        path.write_text(json.dumps(packet))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            apply_reviews(self.path, path, self.root / 'bad.json', 'reviewed-test-1')


if __name__ == '__main__':
    unittest.main()
