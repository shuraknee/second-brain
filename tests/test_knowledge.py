#!/usr/bin/env python3
"""Knowledge import: preserve user data, reject unsafe paths, handle retries."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('knowledge', ROOT / 'tools/knowledge.py')
knowledge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(knowledge)


class KnowledgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='knowledge-', dir=ROOT / 'dist')
        self.base = Path(self.temp.name)
        self.space = self.base / 'пространство % $'
        self.space.mkdir()
        self.pages = knowledge.bundle_files()

    def tearDown(self):
        self.temp.cleanup()

    def test_inspect_does_not_create_directories(self):
        report = knowledge.install_pages(self.space)
        self.assertTrue(report['ok'])
        self.assertEqual(set(report['pending']), set(self.pages))
        self.assertEqual(list(self.space.iterdir()), [])

    def test_import_preserves_notes_and_is_idempotent(self):
        note = self.space / 'index.md'
        note.write_text('Existing user index\n')
        agents = self.space / 'AGENTS.md'
        agents.write_text('Existing organizational instructions\n')
        result = knowledge.install_pages(self.space, apply=True)
        self.assertTrue(result['ok'])
        self.assertEqual(set(result['created']), set(self.pages))
        stamps = {}
        for name, content in self.pages.items():
            self.assertEqual((self.space / name).read_bytes(), content)
            self.assertEqual((self.space / name).stat().st_mode & 0o777, 0o600)
            self.assertEqual((self.space / name).stat().st_nlink, 1)
            stamps[name] = (self.space / name).stat().st_mtime_ns
        repeat = knowledge.install_pages(self.space, apply=True)
        self.assertEqual(repeat['created'], [])
        self.assertEqual(set(repeat['unchanged']), set(self.pages))
        self.assertEqual(stamps, {name: (self.space / name).stat().st_mtime_ns for name in self.pages})
        self.assertEqual(note.read_text(), 'Existing user index\n')
        self.assertEqual(agents.read_text(), 'Existing organizational instructions\n')

    def test_conflict_blocks_entire_import_before_first_write(self):
        name = sorted(self.pages)[-1]
        path = self.space / name
        path.parent.mkdir(parents=True)
        path.write_text('Customized instruction')
        result = knowledge.install_pages(self.space, apply=True)
        self.assertFalse(result['ok'])
        self.assertEqual(result['conflicts'], [name])
        self.assertEqual(result['created'], [])
        self.assertEqual(list(self.space.rglob('*.md')), [path])
        self.assertEqual(path.read_text(), 'Customized instruction')

    def test_symlinked_space_parent_and_destination_are_refused(self):
        link = self.base / 'linked-space'
        link.symlink_to(self.space, target_is_directory=True)
        with self.assertRaises(OSError):
            knowledge.install_pages(link, apply=True)
        outside = self.base / 'outside'
        outside.mkdir()
        (self.space / 'Library').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            knowledge.install_pages(self.space, apply=True)
        self.assertEqual(list(outside.iterdir()), [])
        (self.space / 'Library').unlink()
        name = next(iter(self.pages))
        path = self.space / name
        path.parent.mkdir(parents=True)
        protected = outside / 'protected.md'
        protected.write_bytes(b'preserve')
        path.symlink_to(protected)
        with self.assertRaises(OSError):
            knowledge.install_pages(self.space, apply=True)
        path.unlink()
        os.link(protected, path)
        with self.assertRaises(ValueError):
            knowledge.install_pages(self.space, apply=True)
        self.assertEqual(protected.read_bytes(), b'preserve')

    def test_changed_bundle_is_refused_before_target_write(self):
        bundle = self.base / 'bundle'
        shutil.copytree(ROOT / 'knowledge-base', bundle)
        name = next(iter(self.pages))
        (bundle / 'pages' / name).write_text('Changed download')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            knowledge.install_pages(self.space, apply=True, bundle=bundle)
        self.assertEqual(list(self.space.iterdir()), [])

    def test_manifest_cannot_target_an_unrelated_page(self):
        bundle = self.base / 'bundle'
        shutil.copytree(ROOT / 'knowledge-base', bundle)
        manifest = json.loads((bundle / 'manifest.json').read_text())
        manifest['files']['../users.json'] = '0' * 64
        (bundle / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'Invalid knowledge page'):
            knowledge.install_pages(self.space, apply=True, bundle=bundle)
        self.assertEqual(list(self.space.iterdir()), [])

    def test_concurrent_creation_is_not_overwritten_and_can_be_resumed(self):
        original = knowledge.create_page
        second = sorted(self.pages)[1]

        def concurrent(root_fd, name, content):
            if name == second:
                path = self.space / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'Concurrent user edit')
            return original(root_fd, name, content)

        with patch.object(knowledge, 'create_page', side_effect=concurrent):
            report = knowledge.install_pages(self.space, apply=True)
        self.assertFalse(report['ok'])
        self.assertIn('error', report)
        self.assertEqual(len(report['created']), 1)
        self.assertEqual((self.space / second).read_bytes(), b'Concurrent user edit')
        self.assertEqual(list(self.space.rglob('.second-brain-import-*')), [])
        # Operator retains/reviews the conflicting page; nothing silently deletes it.
        again = knowledge.install_pages(self.space, apply=True)
        self.assertEqual(again['conflicts'], [second])
        self.assertEqual(again['created'], [])

    def test_fresh_seed_resolves_default_and_configured_space_paths(self):
        data = self.base / 'server'
        default = data / 'spaces' / 'abc-123'
        default.mkdir(parents=True)
        configured = data / 'custom-notes'
        configured.mkdir()
        (data / 'spaces.json').write_text(json.dumps({
            'abc-123': {'folder': ''}, 'def-456': {'folder': 'custom-notes'}}))
        reports = knowledge.seed_fresh_spaces(data)
        self.assertEqual(len(reports), 2)
        self.assertTrue(all(r['ok'] for r in reports))
        for root in [default, configured]:
            self.assertEqual(set(p.relative_to(root).as_posix() for p in root.rglob('*.md')), set(self.pages))

    def test_relative_and_dotdot_targets_are_rejected(self):
        for path in ['relative', str(self.space / '..' / 'other')]:
            with self.assertRaises(ValueError):
                knowledge.install_pages(path, apply=True)

    def test_repeat_inspection_does_not_leak_file_descriptors(self):
        before = len(list(Path('/proc/self/fd').iterdir()))
        for unused in range(20):
            knowledge.install_pages(self.space)
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), before)


if __name__ == '__main__':
    (ROOT / 'dist').mkdir(exist_ok=True)
    unittest.main()
