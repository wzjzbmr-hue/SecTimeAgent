"""Behavior checks: lock integrity, non-execution, quarantine and offline lookup."""
import argparse
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import poc_catalog as catalog


class CatalogTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.prefix = Path(self.temp.name)
        self.repo = self.prefix / 'pocs' / 'example'
        self.repo.mkdir(parents=True)
        self.run_git('init')
        self.run_git('remote', 'add', 'origin', 'https://github.com/example/source.git')
        # Merely indexing must not execute top-level source, even when syntax passes.
        self.marker = self.prefix / 'executed'
        (self.repo / 'CVE-2025-12345.py').write_text(
            "from pathlib import Path\nPath(" + repr(str(self.marker)) + ").touch()\n"
            "import missing_cairn_fixture_dependency\n", encoding='utf-8')
        (self.repo / 'old.py').write_text("print 'python two'\n", encoding='utf-8')
        (self.repo / 'README.md').write_text('# Example database\nCVE-2025-12345\n', encoding='utf-8')
        (self.repo / 'CVE-2028-99999.py').write_text('pass\n', encoding='utf-8')
        self.run_git('add', '.')
        self.run_git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@local.invalid', 'commit', '-qm', 'fixture')
        self.source = {'id': 'example', 'url': 'https://github.com/example/source.git',
                       'path': 'pocs/example', 'commit': self.run_git('rev-parse', 'HEAD'),
                       'kind': 'script', 'historical': False}
        self.lock = {'schema_version': 1, 'as_of': '2026-11-23', 'sources': [self.source]}
        self.index = self.prefix / 'index.jsonl'
        catalog.build_index(self.lock, self.prefix, self.index)

    def run_git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], stderr=subprocess.DEVNULL).decode().strip()

    def test_index_does_not_execute_and_blocks_python2(self):
        entries = list(catalog.read_index(self.index, self.lock))
        self.assertFalse(self.marker.exists())
        old = next(x for x in entries if x['path'] == 'old.py')
        self.assertEqual('failed', old['python']['syntax'])
        doc = next(x for x in entries if x['path'] == 'README.md')
        self.assertEqual('knowledge', doc['kind'])
        future = next(x for x in entries if '2028' in x['path'])
        self.assertEqual([], future['cves'])
        self.assertTrue(future['warnings'])

    def test_missing_import_is_blocked_without_executing(self):
        args = argparse.Namespace(index=self.index, prefix=self.prefix, source='example', path='CVE-2025-12345.py')
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(2, catalog.check(args, self.lock))
        self.assertIn('missing_cairn_fixture_dependency', out.getvalue())
        self.assertFalse(self.marker.exists())

    def test_changed_asset_and_index_are_rejected(self):
        (self.repo / 'old.py').write_text('pass\n')
        with self.assertRaises(ValueError):
            catalog.build_index(self.lock, self.prefix, self.index)
        self.index.write_text('{}\n')
        with self.assertRaises(ValueError):
            list(catalog.read_index(self.index, self.lock))

    def test_offline_sync_refuses_mismatch_and_dirty_checkout(self):
        catalog.sync(self.lock, self.prefix, None, True)
        self.source['commit'] = '0' * 40
        with self.assertRaises(ValueError):
            catalog.sync(self.lock, self.prefix, None, True)
        (self.repo / 'old.py').write_text('changed\n')
        with self.assertRaises(ValueError):
            catalog.sync(self.lock, self.prefix, None, False)

    def test_search_filters_and_historical_opt_in(self):
        args = argparse.Namespace(index=self.index, query=['database'], cve='CVE-2025-12345',
                                  kind='knowledge', include_historical=False, limit=10)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            catalog.search(args, self.lock)
        self.assertEqual('README.md', json.loads(out.getvalue())['path'])
        self.source['historical'] = True
        catalog.build_index(self.lock, self.prefix, self.index)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            catalog.search(args, self.lock)
        self.assertEqual('', out.getvalue())

    def test_lock_and_path_tampering_rejected(self):
        for path in ['../outside', '/outside', 'C:\\outside']:
            self.source['path'] = path
            lockfile = self.prefix / 'bad.json'
            lockfile.write_text(json.dumps(self.lock))
            with self.assertRaises(ValueError):
                catalog.load_lock(lockfile)

    def test_historical_id_lookup_without_relabeling_current_cve(self):
        path = self.repo / 'CVE-2025-12345.py'
        review = {'source': 'example', 'commit': self.source['commit'],
                  'renamed': [{'old_cve': 'CVE-2024-99999', 'new_path': path.name,
                               'new_sha256': catalog.file_hash(path), 'note': 'historical identity corrected'}],
                  'withdrawn': [], 'known_warnings': []}
        catalog.build_index(self.lock, self.prefix, self.index, review=review)
        args = argparse.Namespace(index=self.index, query=[], cve='CVE-2024-99999',
                                  kind=None, include_historical=False, limit=10)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            catalog.search(args, self.lock)
        item = json.loads(out.getvalue())
        self.assertEqual('historical_identifier', item['matched_by'])
        self.assertNotIn('CVE-2024-99999', item['cves'])

    def test_unknown_warning_must_not_be_accepted(self):
        expected = "Failed to evaluate expression 'randstr': No parameter 'randstr' found."
        known = [{'message': expected}]
        self.assertEqual('passed_with_known_warning', catalog.validation_verdict(0, '[WRN] '+expected, known))
        self.assertEqual('failed', catalog.validation_verdict(0, '[WRN] new warning', known))
        self.assertEqual('failed', catalog.validation_verdict(1, '[WRN] '+expected, known))


if __name__ == '__main__':
    unittest.main()
