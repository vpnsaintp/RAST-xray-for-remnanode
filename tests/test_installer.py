import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import install


class InstallerTests(unittest.TestCase):
    def test_compose_env_round_trip_preserves_existing_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            env = project / '.env'
            original = 'SECRET_KEY=placeholder-without-newline'
            env.write_text(original, encoding='utf-8')
            value, separator = install.set_compose_env(project, ['docker-compose.yml'])
            self.assertTrue(separator)
            self.assertIn('compose.rast.yaml', env.read_text(encoding='utf-8'))
            install.clear_compose_env(project, value, separator)
            self.assertEqual(env.read_text(encoding='utf-8'), original)

    def test_new_compose_env_removed_on_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            value, separator = install.set_compose_env(project, ['compose.yaml'])
            install.clear_compose_env(project, value, separator)
            self.assertFalse((project / '.env').exists())

    def test_changed_env_blocks_automatic_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            value, separator = install.set_compose_env(project, ['compose.yaml'])
            with (project / '.env').open('a', encoding='utf-8') as out:
                out.write('NEW_SETTING=1\n')
            with self.assertRaises(install.InstallError):
                install.clear_compose_env(project, value, separator)

    def test_preflight_refuses_wrong_image_before_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / 'compose.yaml').write_text('services: {}\n', encoding='utf-8')
            fake = json.dumps({'services': {'remnanode': {'image': 'remnawave/node:latest'}}})
            with patch.object(install, 'run', return_value=fake):
                with self.assertRaisesRegex(install.InstallError, '3.4.3'):
                    install.preflight(project)
            self.assertFalse((project / install.OVERRIDE).exists())

    def test_override_mount_is_read_only(self):
        output = install.render_override(Path('/opt/rast-xray/hash/xray'))
        self.assertIn('/usr/local/bin/xray:ro', output)

    @unittest.skipUnless(shutil.which('docker'), 'Docker Compose недоступен')
    def test_real_docker_compose_accepts_generated_override(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / 'compose.yaml').write_text(
                'services:\n  remnanode:\n    image: remnawave/node:3.4.3\n', encoding='utf-8')
            (project / install.OVERRIDE).write_text(
                install.render_override(Path('/opt/rast-xray/hash/xray')), encoding='utf-8')
            proc = subprocess.run(
                ['docker', 'compose', '-f', 'compose.yaml', '-f', install.OVERRIDE,
                 'config', '--format', 'json'], cwd=project, text=True, capture_output=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            volumes = json.loads(proc.stdout)['services']['remnanode']['volumes']
            self.assertTrue(any(v['target'] == '/usr/local/bin/xray' and v['read_only']
                                for v in volumes))


if __name__ == '__main__':
    unittest.main()
