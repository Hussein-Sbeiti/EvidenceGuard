import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from app.train_adapter import load_export, readiness, run, tokenize_examples
from app.training_data import DEFAULT_DATASET, prepare, record_digest


class FakeTokenizer:
    pad_token_id = 0

    def apply_chat_template(self, messages, tokenize, add_generation_prompt):
        return [1, 2, 3] if add_generation_prompt else [1, 2, 3, 4, 5]

    def save_pretrained(self, path):
        pass


class AdapterRunnerTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        data = json.loads(DEFAULT_DATASET.read_text())
        for record in data['records']:
            for state in ('review', 'screening'):
                record[state] = {'status': 'approved', 'reviewer': 'test-reviewer', 'date': '2026-11-23',
                                 'rationale': 'Synthetic test approval only.', 'record_sha256': record_digest(record)}
        self.dataset = self.root / 'dataset.json'
        self.dataset.write_text(json.dumps(data))
        self.export = self.root / 'export'
        prepare(self.dataset, self.export)

    def test_export_matches_approved_data_and_has_no_test_examples(self):
        manifest, examples = load_export(self.dataset, self.export)
        self.assertEqual(set(examples), {'train', 'validation'})
        self.assertEqual(len(examples['train']), manifest['explanation_counts']['train'])

    def test_unapproved_dataset_cannot_be_loaded(self):
        with self.assertRaisesRegex(ValueError, 'approved review'):
            load_export(DEFAULT_DATASET, self.export)

    def test_tampered_export_rejected_even_if_manifest_file_hash_is_changed(self):
        path = self.export / 'explanation.train.jsonl'
        path.write_text(path.read_text().replace('Keep the query template', 'Ignore the query template'))
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            load_export(self.dataset, self.export)
        manifest_path = self.export / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        manifest['file_sha256'][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'differs from approved'):
            load_export(self.dataset, self.export)

    def test_split_and_prompt_changes_require_a_new_export(self):
        path = self.export / 'manifest.json'
        manifest = json.loads(path.read_text())
        manifest['splits']['train'].append('made-up-record')
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'split manifest'):
            load_export(self.dataset, self.export)

    def test_labels_mask_prompt_tokens_and_never_truncate_completion(self):
        _, examples = load_export(self.dataset, self.export)
        rows = tokenize_examples(examples['train'][:1], FakeTokenizer())
        self.assertEqual(rows[0]['labels'], [-100, -100, -100, 4, 5])
        self.assertEqual(rows[0]['attention_mask'], [1] * 5)
        with self.assertRaisesRegex(ValueError, 'exceeds'):
            tokenize_examples(examples['train'][:1], FakeTokenizer(), max_length=4)

    def test_incompatible_chat_template_is_rejected(self):
        _, examples = load_export(self.dataset, self.export)
        tokenizer = Mock()
        tokenizer.apply_chat_template.side_effect = [[1, 2], [1, 8, 4]]
        with self.assertRaisesRegex(ValueError, 'assistant prefix'):
            tokenize_examples(examples['train'][:1], tokenizer)

    def test_revision_and_dependency_failures_do_not_create_run(self):
        output = self.root / 'run'
        with self.assertRaisesRegex(ValueError, 'immutable'):
            run(self.dataset, self.export, output, 'main')
        with patch('app.train_adapter._installed', return_value=False):
            with self.assertRaisesRegex(ValueError, 'separate environment'):
                run(self.dataset, self.export, output, 'a' * 40)
        self.assertFalse(output.exists())

    def test_readiness_does_not_treat_drafts_as_trainable(self):
        result = readiness()
        self.assertEqual(result['unapproved_records'], 18)
        self.assertFalse(result['data_and_packages_ready'])
        self.assertFalse(result['training_performed'])

    def test_smoke_runner_wiring_with_mock_libraries(self):
        torch = Mock()
        torch.cuda.is_available.return_value = True
        torch.cuda.is_bf16_supported.return_value = True
        torch.cuda.get_device_name.return_value = 'Mock GPU'
        torch.cuda.max_memory_allocated.return_value = 123
        torch.version.hip = None
        model = Mock()
        transformer = Mock()
        transformer.AutoTokenizer.from_pretrained.return_value = FakeTokenizer()
        transformer.AutoModelForCausalLM.from_pretrained.return_value = model
        trainer = transformer.Trainer.return_value
        trainer.evaluate.side_effect = [{'eval_loss': 2.0}, {'eval_loss': 1.9}]
        peft = Mock()
        peft.get_peft_model.return_value = model
        output = self.root / 'smoke'
        with patch.dict('sys.modules', {'torch': torch, 'transformers': transformer, 'peft': peft}), \
                patch.dict('os.environ', {}, clear=False), \
                patch('app.train_adapter._installed', return_value=True), \
                patch('app.train_adapter.importlib.metadata.version', return_value='mock-version'):
            result = run(self.dataset, self.export, output, 'a' * 40, smoke=True)
        self.assertEqual(result['status'], 'complete')
        self.assertTrue(result['training_started'])
        self.assertFalse(result['deployment_approved'])
        transformer.TrainingArguments.assert_called_once()
        args = transformer.TrainingArguments.call_args.kwargs
        self.assertEqual(args['max_steps'], 1)
        self.assertEqual(args['report_to'], 'none')
        self.assertFalse(args['push_to_hub'])
        self.assertTrue(transformer.AutoModelForCausalLM.from_pretrained.call_args.kwargs['local_files_only'])
        trainer.train.assert_called_once()
        self.assertEqual(json.loads((output / 'run.json').read_text())['mode'], 'smoke')


if __name__ == '__main__':
    unittest.main()
