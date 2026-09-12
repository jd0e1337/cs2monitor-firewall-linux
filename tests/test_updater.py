import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cs2monitor as app


def fixture():
    return {'schemaVersion': 2, 'categories': ['abuse'], 'includePorts': True,
            'includeDerived': True, 'generatedAt': int(time.time()*1000), 'count': 4,
            'items': [{'type': 'ip', 'value': '8.8.8.8'}, {'type': 'subnet', 'value': '8.8.8.0/24'},
                      {'type': 'server_address', 'value': '193.23.195.8:27013'},
                      {'type': 'server_address', 'value': '193.23.195.8:27013'}]}


class Validation(unittest.TestCase):
    def test_port_scope_and_overlap(self):
        networks, ports = app.validate(fixture())
        self.assertEqual(list(map(str, networks)), ['8.8.8.0/24'])
        self.assertEqual(ports, [('193.23.195.8', 27013)])
        output = app.render(fixture())
        self.assertIn('193.23.195.8 . 27013', output)
        self.assertIn('tcp dport @endpoints', output)
        self.assertIn('udp dport @endpoints', output)
        self.assertNotIn('flush ruleset', output)

    def test_reject_invalid_lists(self):
        cases = [('categories', ['abuse','unclassified']), ('includePorts', False),
                 ('includeDerived', False), ('schemaVersion', 1), ('count', 5),
                 ('items', []), ('generatedAt', 1), ('generatedAt', float('nan'))]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                data = fixture(); data[key] = value
                with self.assertRaises(ValueError): app.validate(data)

    def test_reject_unsafe_addresses(self):
        for kind, value in [('ip','127.0.0.1'), ('ip','10.0.0.1'), ('subnet','0.0.0.0/0'),
                            ('server_address','193.23.195.8:65536'), ('server_address','193.23.195.8:0'),
                            ('server_address','193.23.195.8:27013; flush ruleset'), ('ip','::1')]:
            data = fixture(); data['items'][0] = dict(type=kind,value=value)
            with self.subTest(value=value), self.assertRaises(ValueError): app.validate(data)

    def test_boot_restore_allows_old_but_still_validates(self):
        data = fixture(); data['generatedAt'] = 1
        self.assertIn('table inet cs2monitor', app.render(data, fresh=False))
        data['categories'] = ['restricted']
        with self.assertRaises(ValueError): app.render(data, fresh=False)

    def test_atomic_replace_only_owned_table(self):
        with patch.object(app, 'table_exists', return_value=True), patch.object(app, 'run') as run:
            app.apply(fixture())
            self.assertEqual(run.call_count, 2)
            text = run.call_args.args[1]
            self.assertTrue(text.startswith('delete table inet cs2monitor\n'))
            self.assertNotIn('flush ruleset', text)
            self.assertEqual(run.call_args_list[0].args[0], ['nft','--check','-f','-'])

    def test_failed_apply_preserves_last_good(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory); old = state/'last-good.json'; old.write_text('old')
            with patch.object(app,'STATE',state), patch.object(app,'download',return_value=fixture()), patch.object(app,'apply',side_effect=ValueError('rejected')):
                with self.assertRaises(ValueError): app.update()
            self.assertEqual(old.read_text(), 'old')

    def test_firewall_manager_refusal(self):
        with patch.object(Path,'is_dir',return_value=True), patch.object(app.shutil,'which',return_value='/bin/tool'), patch.object(app.subprocess,'run') as run:
            run.return_value.returncode = 0
            with self.assertRaisesRegex(ValueError,'not supported'): app.check_environment()

    def test_distribution_dependencies(self):
        for info, expected in [({'ID':'arch'},'pacman -Syu'), ({'ID':'endeavouros','ID_LIKE':'arch'},'pacman -Syu'),
                               ({'ID':'manjaro'},'pacman -Syu'), ({'ID':'ubuntu'},'apt install'),
                               ({'ID':'fedora'},'dnf install'), ({'ID':'opensuse-tumbleweed'},'zypper install')]:
            with self.subTest(info=info): self.assertIn(expected, app.dependency_command(info))

    def test_requires_running_systemd(self):
        with patch.object(Path,'is_dir',return_value=False), self.assertRaisesRegex(ValueError,'running systemd'):
            app.check_environment()

    def test_lifecycle_files_and_uninstall_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory); state=base/'state'; units=base/'units'; program=base/'lib/app.py'
            units.mkdir(); unrelated=units/'unrelated.service'; unrelated.write_text('keep')
            def fake_update(): app.atomic_write(state/'last-good.json', json.dumps(fixture()))
            with patch.object(app,'STATE',state), patch.object(app,'UNITS',units), patch.object(app,'PROGRAM',program), patch.object(app,'table_exists',return_value=False), patch.object(app,'update',side_effect=fake_update), patch.object(app,'run'):
                app.install(True)
                self.assertTrue(program.exists())
                self.assertIn('OnUnitActiveSec=3h', (units/'cs2monitor-firewall-update.timer').read_text())
                app.install(False)
                app.uninstall()
                self.assertFalse(program.exists()); self.assertFalse((state/'last-good.json').exists())
                self.assertEqual(unrelated.read_text(),'keep')


if __name__ == '__main__': unittest.main()
