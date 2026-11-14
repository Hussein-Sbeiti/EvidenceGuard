import io
import json
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from fastapi import UploadFile

from app.dependency_intelligence import DependencyIntelligence, normalize_record
from app.intelligence import Intelligence
from app.main import scan
from app.manifests import parse_manifest


def locked(packages, version=3):
    return json.dumps({'lockfileVersion': version, 'packages': {'': {'name': 'root'}, **packages}})


def advisory(identifier='GHSA-test-0001', name='requests', ecosystem='PyPI'):
    return {'id': identifier, 'summary': 'Synthetic advisory', 'aliases': ['CVE-2020-0001'],
            'database_specific': {'severity': 'HIGH'}, 'affected': [{'package': {'ecosystem': ecosystem, 'name': name},
                'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '3.0.0'}]},
                           {'type': 'GIT', 'events': [{'fixed': 'commit-hash'}]}], 'versions': ['2.0.0']}]}


class ManifestTests(unittest.TestCase):
    def test_python_pins_ranges_markers_extras_hashes_and_line_locations(self):
        source = '# fixture\nRequests[socks]==2.19.1 \\\n    --hash=sha256:abc\nDjango>=2\nflask\nPyYAML==5.3.1; python_version < "3.8"\n'
        entries, issues = parse_manifest('src/requirements.txt', source)
        self.assertEqual(issues, [])
        self.assertEqual([(entry['name'], entry['status']) for entry in entries], [('requests', 'exact'), ('django', 'unresolved'), ('flask', 'unresolved'), ('pyyaml', 'exact')])
        self.assertEqual(entries[0]['version'], '2.19.1')
        self.assertEqual(entries[0]['line'], 2)
        self.assertEqual(entries[0]['extras'], ['socks'])
        self.assertTrue(entries[-1]['conditional'])
        self.assertIn('python_version', entries[-1]['marker'])

    def test_python_references_and_variables_are_not_resolved_or_echoed(self):
        source = '-r https://user:private-token@example.test/private\npkg @ https://user:private-token@example.test/a.whl\npkg==${PRIVATE_VERSION}\n'
        entries, _ = parse_manifest('requirements.txt', source)
        self.assertTrue(all(entry['status'] == 'unresolved' for entry in entries))
        self.assertNotIn('private-token', json.dumps(entries))
        self.assertNotIn('PRIVATE_VERSION', json.dumps(entries))

    def test_conflicts_wildcards_and_multiple_constraints_stay_unresolved(self):
        entries, _ = parse_manifest('requirements.txt', 'pkg==1.0\npkg==2.0\nother==1.*\nanother==1.0,<2\n')
        self.assertTrue(all(entry['status'] == 'unresolved' for entry in entries))

    def test_python_index_options_do_not_send_assumed_public_package_identity(self):
        entries, _ = parse_manifest('requirements.txt', '--index-url https://user:private-token@private.test/simple\nrequests==2.0.0')
        self.assertTrue(all(entry['status'] == 'unresolved' for entry in entries))
        self.assertNotIn('private-token', json.dumps(entries))

    def test_modern_npm_nested_scoped_alias_and_links(self):
        source = locked({'node_modules/lodash': {'version': '4.17.15'},
                         'node_modules/a/node_modules/@scope/pkg': {'version': '1.2.3-beta.1'},
                         'node_modules/alias': {'name': 'real-package', 'version': '2.0.0'},
                         'node_modules/local': {'link': True, 'resolved': 'packages/local'},
                         'node_modules/missing': {}, 'node_modules/range': {'version': '^1.0.0'}})
        entries, issues = parse_manifest('package-lock.json', source)
        self.assertEqual(issues, [])
        self.assertEqual([item['name'] for item in entries[:3]], ['lodash', '@scope/pkg', 'real-package'])
        self.assertTrue(all(item['status'] == 'exact' for item in entries[:3]))
        self.assertTrue(all(item['status'] == 'unresolved' for item in entries[3:]))
        self.assertEqual(entries[1]['location'], '/packages/node_modules~1a~1node_modules~1@scope~1pkg/version')

    def test_legacy_npm_alias_and_transitive_versions(self):
        source = json.dumps({'lockfileVersion': 1, 'dependencies': {'alias': {'version': 'npm:@scope/real@1.2.3', 'dependencies': {'child': {'version': '2.0.0'}}}}})
        entries, _ = parse_manifest('package-lock.json', source)
        self.assertEqual([(item['name'], item['version']) for item in entries], [('@scope/real', '1.2.3'), ('child', '2.0.0')])

    def test_npm_optional_target_and_dev_context_is_retained(self):
        entries, _ = parse_manifest('package-lock.json', locked({'node_modules/JSONStream': {'version': '1.3.5', 'dev': True, 'optional': True, 'os': ['linux']}}))
        self.assertEqual(entries[0]['status'], 'exact')
        self.assertTrue(entries[0]['conditional'])
        self.assertTrue(entries[0]['dev'])
        self.assertTrue(entries[0]['optional'])

    def test_npm_private_and_direct_sources_remain_unresolved(self):
        source = locked({'node_modules/pkg': {'version': '1.2.3', 'resolved': 'https://user:private-token@private.test/pkg.tgz'},
                         'node_modules/git': {'version': 'git+https://example.test/pkg'}})
        entries, _ = parse_manifest('package-lock.json', source)
        self.assertTrue(all(item['status'] == 'unresolved' for item in entries))
        self.assertNotIn('private-token', json.dumps(entries))

    def test_invalid_duplicate_json_and_bounded_inventory(self):
        for source in ['[]', '{', '{"lockfileVersion":3,"packages":{},"packages":{}}', '{"lockfileVersion":8}']:
            with self.subTest(source=source):
                entries, issues = parse_manifest('package-lock.json', source)
                self.assertEqual(entries, [])
                self.assertTrue(issues)
        entries, issues = parse_manifest('requirements.txt', 'a==1\nb==2\nc==3', limit=2)
        self.assertEqual(len(entries), 2)
        self.assertIn('truncated', issues[0]['message'])


class OsvTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = 1000000.0
        self.requests = []
        self.payloads = [{'vulns': [advisory()]}]
        def opener(request, timeout):
            self.requests.append(request)
            payload = self.payloads.pop(0)
            if isinstance(payload, Exception):
                raise payload
            return io.BytesIO(json.dumps(payload).encode())
        self.transport = Intelligence(str(Path(self.temp.name) / 'cache.db'), api_key='private-nvd-key', opener=opener, clock=lambda: self.now)
        self.service = DependencyIntelligence(self.transport, monotonic=lambda: self.now, sleeper=self.advance)
        self.entries = [{'file': 'requirements.txt', 'location': 'line 1', 'line': 1, 'conditional': False, 'status': 'exact', 'ecosystem': 'PyPI', 'name': 'requests', 'version': '2.0.0'}]

    def advance(self, seconds):
        self.now += seconds

    def test_query_sends_only_identity_and_caches_provenance_and_fixed_versions(self):
        result = self.service.lookup_many(self.entries, True)[0]
        self.assertEqual(result['status'], 'live')
        self.assertEqual(result['advisories'][0]['fixed_versions'], ['3.0.0'])
        self.assertEqual(result['advisories'][0]['applicability'], 'osv_reported_version_match')
        self.assertEqual(json.loads(self.requests[0].data), {'package': {'ecosystem': 'PyPI', 'name': 'requests'}, 'version': '2.0.0'})
        self.assertNotIn('private-nvd-key', str(self.requests[0].header_items()))
        self.assertEqual(self.service.lookup_many(self.entries, True)[0]['status'], 'cached')
        self.assertEqual(len(self.requests), 1)

    def test_disabled_never_opens_cache_or_network(self):
        with patch.object(self.transport, 'connect', side_effect=AssertionError('offline')):
            self.assertEqual(self.service.lookup_many(self.entries)[0]['status'], 'disabled')
        self.assertEqual(self.requests, [])

    def test_duplicate_identity_retains_both_manifest_locations(self):
        duplicate = {**self.entries[0], 'file': 'nested/requirements.txt'}
        results = self.service.lookup_many([*self.entries, duplicate], True)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0]['locations']), 2)
        self.assertEqual(len(self.requests), 1)

    def test_empty_response_is_complete_but_bad_payload_is_not_clean(self):
        self.payloads = [{}]
        result = self.service.lookup_many(self.entries, True)[0]
        self.assertTrue(result['complete'])
        self.assertEqual(result['advisories'], [])
        self.now += 86401
        self.payloads = [{'vulns': None}]
        result = self.service.lookup_many(self.entries, True)[0]
        self.assertEqual(result['status'], 'stale')
        self.assertIn('invalid', result['warning'])

    def test_pagination_resumes_from_cache_after_request_budget(self):
        self.payloads = [{'vulns': [advisory('first')], 'next_page_token': 'page-two'}, {'vulns': [advisory('second')]}]
        with patch('app.dependency_intelligence.MAX_OSV_REQUESTS', 1):
            first = self.service.lookup_many(self.entries, True)[0]
            self.assertEqual(first['status'], 'partial')
            self.assertFalse(first['complete'])
            second = self.service.lookup_many(self.entries, True)[0]
        self.assertTrue(second['complete'])
        self.assertEqual([item['id'] for item in second['advisories']], ['first', 'second'])
        self.assertEqual(json.loads(self.requests[-1].data)['page_token'], 'page-two')

    def test_pagination_failure_retains_successful_first_page(self):
        self.payloads = [{'vulns': [advisory()], 'next_page_token': 'more'}, {'vulns': None}]
        result = self.service.lookup_many(self.entries, True)[0]
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(len(result['advisories']), 1)
        self.assertFalse(result['complete'])

    def test_429_cooldown_and_stale_fallback(self):
        self.service.lookup_many(self.entries, True)
        self.now += 86401
        self.payloads = [HTTPError('https://api.osv.dev/v1/query', 429, 'limited', {'Retry-After': '120'}, None)]
        self.assertEqual(self.service.lookup_many(self.entries, True)[0]['status'], 'stale')
        self.advance(61)
        self.assertEqual(self.service.lookup_many(self.entries, True)[0]['status'], 'stale')
        self.assertEqual(len(self.requests), 2)

    def test_budget_and_nonmatching_evidence_do_not_claim_complete_match(self):
        with patch('app.dependency_intelligence.MAX_OSV_REQUESTS', 0):
            result = self.service.lookup_many(self.entries, True)[0]
        self.assertEqual(result['status'], 'deferred')
        self.assertFalse(result['complete'])
        record = normalize_record(advisory(name='other-package'), 'PyPI', 'requests')
        self.assertEqual(record['applicability'], 'unverified_package_identity')
        self.assertEqual(record['fixed_versions'], [])

    def test_advisory_cap_is_partial_and_withdrawal_is_preserved(self):
        self.payloads = [{'vulns': [advisory('first'), advisory('second')]}]
        with patch('app.dependency_intelligence.MAX_ADVISORIES', 1):
            result = self.service.lookup_many(self.entries, True)[0]
        self.assertEqual(result['status'], 'partial')
        self.assertFalse(result['complete'])
        self.assertEqual(len(result['advisories']), 1)
        withdrawn = normalize_record({**advisory(), 'withdrawn': '2020-01-01T00:00:00Z'}, 'PyPI', 'requests')
        self.assertEqual(withdrawn['applicability'], 'withdrawn')

    def test_corrupt_normalized_cache_is_discarded(self):
        self.service.lookup_many(self.entries, True)
        with closing(self.transport.connect()) as db, db:
            db.execute("UPDATE cache SET payload=? WHERE provider='OSV'", (json.dumps({'complete': True, 'advisories': ['invalid']}),))
        self.now += 2
        self.payloads = [{'vulns': [advisory()]}]
        self.assertEqual(self.service.lookup_many(self.entries, True)[0]['status'], 'live')
        self.assertEqual(len(self.requests), 2)


class DependencyUploadTests(unittest.IsolatedAsyncioTestCase):
    async def test_manifests_only_scan_inventory_and_no_network_by_default(self):
        content = b'requests==2.19.1\nflask>=2\n'
        buffer = io.BytesIO(content)
        with patch('app.main.intelligence.request_json') as network:
            result = await scan([UploadFile(filename='app/requirements.txt', file=buffer)])
        network.assert_not_called()
        self.assertEqual(result['summary']['files_scanned'], 1)
        self.assertEqual(result['dependency_summary']['exact'], 1)
        self.assertEqual(result['dependency_summary']['unresolved'], 1)
        self.assertEqual(result['dependency_results'][0]['status'], 'disabled')
        self.assertEqual(buffer.getvalue(), content)
        self.assertEqual(result['findings'], [])

    async def test_opt_in_is_separate_from_cve_lookup_and_excludes_unresolved_versions(self):
        with patch('app.main.dependency_intelligence.lookup_many', return_value=[]) as osv, patch('app.main.intelligence.lookup') as cve:
            result = await scan([UploadFile(filename='requirements.txt', file=io.BytesIO(b'requests==2.19.1\n'))], False, True)
        self.assertTrue(osv.call_args.args[1])
        self.assertEqual(osv.call_args.args[0][0]['version'], '2.19.1')
        cve.assert_not_called()
        self.assertTrue(result['dependency_lookup'])
