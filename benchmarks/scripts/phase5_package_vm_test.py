import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name('phase5_package_vm.py')
SPEC = importlib.util.spec_from_file_location('phase5_package_vm', SCRIPT)
vm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vm)
PLAN = SCRIPT.parents[1] / 'results/verification/phase5-package-placement-clean-20260925/24-core-clean-856f043'


class PackageVMTests(unittest.TestCase):
    class Response:
        def __init__(self, body):
            self.status = 200
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, _type, _value, _traceback):
            return False

        def read(self, limit):
            return self.body[:limit]

    def test_package_readiness_keeps_semantic_route_probe(self):
        requests = []

        def open_request(request, timeout):
            requests.append((request, timeout))
            return self.Response(b'x' * 256)

        with patch.object(vm, 'urlopen', side_effect=open_request):
            vm.readiness()
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0][0].full_url,
                         'http://127.0.0.1:8080/payload/256')
        self.assertEqual(requests[0][0].get_header('Host'), 'api.example.test')

    def test_campaign_readiness_retries_loopback_metrics(self):
        requests = []

        def open_request(request, timeout):
            requests.append((request, timeout))
            if len(requests) == 1:
                raise ConnectionRefusedError('listener is still binding')
            return self.Response(b'#')

        with patch.object(vm, 'urlopen', side_effect=open_request), \
             patch.object(vm.time, 'sleep'):
            vm.readiness({'profile_id': 'P5-C00'}, timeout=1)
        self.assertEqual([request.full_url for request, _ in requests], [
            'http://127.0.0.1:9090/metrics',
            'http://127.0.0.1:9090/metrics'])

    def test_campaign_readiness_rejects_unknown_profile(self):
        with self.assertRaisesRegex(RuntimeError,
                                    'campaign readiness profile is invalid'):
            vm.readiness({'profile_id': 'foreign'})

    def test_regular_bytes_consumes_short_reads(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'artifact'
            expected = b'complete-runtime-artifact'
            target.write_bytes(expected)
            original_read = os.read

            def short_read(fd, size):
                return original_read(fd, min(size, 3))

            with patch.object(vm.os, 'read', side_effect=short_read):
                self.assertEqual(vm.regular_bytes(target), expected)

    def runtime_fixture(self, directory, runtime_root=None):
        plan_id = 'a' * 64
        runtime_root = runtime_root or (
            '/run/bonvoyage-perf06/policy-' + plan_id[:16])
        plan = {'source_commit': 'b' * 40,
                'runtime_artifacts': {'root': runtime_root,
                                      'plan_id': plan_id,
                                      'snapshot_file': runtime_root + '/active.pb',
                                      'secrets_directory': runtime_root + '/secrets',
                                      'hosts_file': runtime_root + '/hosts'}}
        root = directory / 'runtime-source'
        (root / 'secrets').mkdir(parents=True)
        values = {
            'active.pb': b'compiled snapshot\n',
            'hosts': b'127.0.0.1 localhost\n',
            'secrets/ca.pem': b'ca\n',
            'secrets/phase5-policy-api-keys.txt': b'private-api-key\n',
            'secrets/phase5-policy-jwks.json': b'{"keys":[]}\n',
            'secrets/server-chain.pem': b'chain\n',
            'secrets/server-key.pem': b'private-server-key\n'}
        metadata = {'schema_version': 1,
                    'evidence_class': 'private-perf06-runtime-bundle',
                    'source_commit': plan['source_commit'],
                    'plan_id': plan_id, 'profile_id': 'P5-B02',
                    'runtime_root': runtime_root,
                    'snapshot_sha256': vm.digest(values['active.pb']),
                    'campaign_manifest_sha256': 'c' * 64}
        values['runtime.json'] = (json.dumps(metadata, indent=2) + '\n').encode()
        for name, value in values.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(value)
        manifest = ''.join(f'{vm.digest(values[name])}  {name}\n'
                           for name in sorted(vm.RUNTIME_FILES)).encode()
        (root / 'checksums.sha256').write_bytes(manifest)
        return plan, root, vm.digest(manifest)

    def test_runtime_bundle_is_exact_and_tamper_evident(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan, root, manifest = self.runtime_fixture(Path(temporary))
            metadata, contents = vm.verify_runtime_bundle(root, manifest, plan)
            self.assertEqual(metadata['profile_id'], 'P5-B02')
            self.assertNotIn('signing/jwt-private.pem', contents)
            (root / 'hosts').write_text('foreign\n')
            with self.assertRaisesRegex(RuntimeError,
                                        'runtime bundle checksums failed'):
                vm.verify_runtime_bundle(root, manifest, plan)

    def test_runtime_staging_is_atomic_and_removable(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            parent = directory / 'run/bonvoyage-perf06'
            runtime_root = parent / ('policy-' + 'a' * 16)
            plan, source, manifest = self.runtime_fixture(
                directory, str(runtime_root))
            record = directory / 'record'
            record.mkdir()
            pattern = re.compile(re.escape(str(parent)) +
                                 r'/[a-z0-9][a-z0-9-]{0,63}$')
            with patch.object(vm, 'CAMPAIGN_PARENT', parent), \
                 patch.object(vm, 'CAMPAIGN_ROOT', pattern), \
                 patch.object(vm.grp, 'getgrnam', return_value=SimpleNamespace(
                     gr_gid=os.getgid())), \
                 patch.object(vm.os, 'chown'), patch.object(vm.os, 'fchown'):
                expectation = vm.stage_runtime(source, manifest, plan, record)
                self.assertTrue(runtime_root.is_dir())
                self.assertFalse((record / 'runtime-staging').exists())
                vm.verify_runtime_expectation(expectation)
                (runtime_root / 'hosts').chmod(0o600)
                with self.assertRaisesRegex(RuntimeError,
                                            'file permissions changed'):
                    vm.verify_runtime_expectation(expectation)
                (runtime_root / 'hosts').chmod(0o644)
                vm.remove_runtime(expectation, record,
                                  {'target_exists': True,
                                   'staging_exists': False})
            self.assertFalse(runtime_root.exists())
            self.assertFalse(parent.exists())

    def test_clean_bundle_and_tamper_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'bundle'
            shutil.copytree(PLAN, directory)
            sha = vm.digest((directory / 'checksums.sha256').read_bytes())
            plan, contents = vm.verify_bundle(directory, sha)
            self.assertFalse(plan['source_dirty'])
            self.assertEqual(len(contents), 5)
            (directory / 'bonvoyage-runtime.conf').write_text('foreign')
            with self.assertRaisesRegex(RuntimeError, 'checksums failed'):
                vm.verify_bundle(directory, sha)

    def test_foreign_member_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'bundle'
            shutil.copytree(PLAN, directory)
            sha = vm.digest((directory / 'checksums.sha256').read_bytes())
            (directory / 'extra').write_text('foreign')
            with self.assertRaisesRegex(RuntimeError, 'membership changed'):
                vm.verify_bundle(directory, sha)
            (directory / 'extra').unlink()
            runtime = directory / 'bonvoyage-runtime.conf'
            runtime.unlink()
            runtime.symlink_to(PLAN / runtime.name)
            with self.assertRaises(OSError):
                vm.verify_bundle(directory, sha)

    def test_cpu_ranges_fail_closed(self):
        self.assertEqual(vm.expand_cpus('0-3,8'), {0, 1, 2, 3, 8})
        for spec in ('3-1', '0-5000', '0,,1', 'x', ''):
            with self.subTest(spec=spec), self.assertRaises(RuntimeError):
                vm.expand_cpus(spec)

    def test_static_ena_affinity_maps_management_and_queues_to_reserved_cpus(self):
        nic = {'interface': 'enp39s0', 'queues': 8,
               'labels': {'70': 'ena-mgmnt@pci:0000:27:00.0',
                          **{str(71 + index): f'enp39s0-Tx-Rx-{index}'
                             for index in range(8)}}}
        self.assertEqual(vm.static_ena_affinity(nic, '0-7'),
                         {'70': '0', **{str(71 + index): str(index)
                                        for index in range(8)}})
        with self.assertRaisesRegex(RuntimeError, 'one planned CPU per queue'):
            vm.static_ena_affinity(nic, '0-6')
        nic['labels']['78'] = 'foreign'
        with self.assertRaisesRegex(RuntimeError, 'unrecognized ENA IRQ label'):
            vm.static_ena_affinity(nic, '0-7')

    def test_irq_affinity_write_requires_effective_convergence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mapping = {'70': '0', '71': '1'}
            for irq in mapping:
                directory = root / irq
                directory.mkdir()
                (directory / 'smp_affinity_list').write_text('31\n')
            with patch.object(vm, 'IRQ_ROOT', root), \
                 patch.object(vm, 'irq_state', return_value={'affinity': mapping}):
                self.assertEqual(vm.apply_irq_affinity(mapping), mapping)
            self.assertEqual((root / '70/smp_affinity_list').read_text(), '0\n')
            self.assertEqual((root / '71/smp_affinity_list').read_text(), '1\n')
            with patch.object(vm, 'IRQ_ROOT', root), \
                 patch.object(vm, 'irq_state', return_value={
                     'affinity': {'70': '0', '71': '2'}}):
                with self.assertRaisesRegex(RuntimeError, 'did not converge'):
                    vm.apply_irq_affinity(mapping)

    def test_active_exclusion_waits_for_all_irqs_inside_reserved_cpus(self):
        before = {'interface': 'enp39s0', 'queues': 2,
                  'labels': {'70': 'ena-mgmnt@pci:0000:27:00.0',
                             '71': 'enp39s0-Tx-Rx-0',
                             '72': 'enp39s0-Tx-Rx-1'}}
        drifting = {**before, 'affinity': {'70': '0', '71': '8', '72': '3'}}
        isolated = {**before, 'affinity': {'70': '0', '71': '2', '72': '3'}}
        with patch.object(vm, 'irq_state', side_effect=[drifting, isolated]):
            self.assertEqual(vm.wait_irq_affinity_allowed(
                before, '0-7', '8-31', timeout=1, poll=0,
                stable_samples=1), isolated)
        with patch.object(vm, 'irq_state', return_value=drifting), \
             patch.object(vm.time, 'monotonic', side_effect=[0, 0, 2]):
            with self.assertRaisesRegex(RuntimeError, 'did not converge'):
                vm.wait_irq_affinity_allowed(before, '0-7', '8-31',
                                             timeout=1, poll=0)

    def test_active_exclusion_requires_stable_convergence(self):
        before = {'interface': 'enp39s0', 'queues': 2,
                  'labels': {'70': 'ena-mgmnt@pci:0000:27:00.0',
                             '71': 'enp39s0-Tx-Rx-0',
                             '72': 'enp39s0-Tx-Rx-1'}}
        drifting = {**before, 'affinity': {'70': '0', '71': '8', '72': '3'}}
        isolated = {**before, 'affinity': {'70': '0', '71': '2', '72': '3'}}
        observations = [isolated, drifting, isolated, isolated]
        with patch.object(vm, 'irq_state', side_effect=observations):
            self.assertEqual(vm.wait_irq_affinity_allowed(
                before, '0-7', '8-31', timeout=1, poll=0,
                stable_samples=2), isolated)

        with self.assertRaisesRegex(RuntimeError, 'sample count invalid'):
            vm.wait_irq_affinity_allowed(before, '0-7', '8-31',
                                         stable_samples=0)

    def test_static_affinity_restore_is_best_effort_on_nitro(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for irq in ('70', '71'):
                directory = root / irq
                directory.mkdir()
                (directory / 'smp_affinity_list').write_text('31\n')
            observed = {'70': '9', '71': '26'}
            with patch.object(vm, 'IRQ_ROOT', root), \
                 patch.object(vm, 'irq_state', return_value={'affinity': observed}):
                result = vm.best_effort_restore_irq_affinity(
                    {'70': '0', '71': '1'})
            self.assertEqual(result['observed'], observed)
            self.assertFalse(result['converged'])
            self.assertEqual(result['write_errors'], {})

    def test_thread_affinity_requires_containment_and_full_pinned_coverage(self):
        valid = [{'tid': 10, 'name': 'reactor-0', 'cpus': '8'},
                 {'tid': 11, 'name': 'reactor-1', 'cpus': '9'},
                 {'tid': 12, 'name': 'helper', 'cpus': '8-9'}]
        with patch.object(vm, 'process_thread_affinity', return_value=valid):
            self.assertEqual(vm.verify_thread_affinity('42', '8-9'), valid)
        escaped = valid + [{'tid': 13, 'name': 'foreign', 'cpus': '0'}]
        with patch.object(vm, 'process_thread_affinity', return_value=escaped):
            with self.assertRaisesRegex(RuntimeError, 'escaped planned CPUs'):
                vm.verify_thread_affinity('42', '8-9')
        incomplete = [valid[0], valid[2]]
        with patch.object(vm, 'process_thread_affinity', return_value=incomplete):
            with self.assertRaisesRegex(RuntimeError, 'do not cover planned CPUs'):
                vm.verify_thread_affinity('42', '8-9')

    def fixture(self, directory, foreign=False):
        root = directory / 'record'
        runtime = directory / 'runtime'
        attempt = root / 'probe'
        attempt.mkdir(parents=True)
        runtime.mkdir()
        controls = {'bonvoyage-resources.conf': runtime / '20-perf01-resources.conf',
                    'bonvoyage-runtime.conf': runtime / '30-perf01-runtime.conf'}
        hashes = {}
        for name, path in controls.items():
            content = name.encode()
            path.write_bytes(content)
            hashes[name] = vm.digest(content)
        if foreign:
            (runtime / 'foreign.conf').write_text('foreign')
        aio = directory / 'aio'
        aio.write_text('524288\n')
        boot = directory / 'boot'
        boot.write_text('boot-1\n')
        state = {'status': 'active', 'control_sha256': hashes,
                 'profile': 'irqbalance-off-unpinned',
                 'helper_sha256': vm.file_digest(SCRIPT),
                 'binary_sha256': 'a' * 64,
                 'planned_aio_max_nr': 524288,
                 'before': {'boot_id': 'boot-1', 'aio_max_nr': 65536,
                            'irqbalance': {'ActiveState': 'active'}}}
        shutil.copyfile(SCRIPT, attempt / 'helper.py')
        vm.write_json(attempt / 'state.json', state)
        return root, runtime, controls, aio, boot

    def test_restore_restarts_gateway_before_lowering_aio(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root, runtime, controls, aio, boot = self.fixture(directory)
            unit = directory / 'bonvoyage.service'
            unit.write_text('ExecStart=/usr/bin/bonvoyage-dataplane --smp 1\n')
            calls = []

            def command(*args):
                calls.append(args)
                if args == ('systemctl', 'restart', 'bonvoyage.service'):
                    self.assertEqual(aio.read_text().strip(), '524288')
                if args == ('systemctl', 'show',
                            'bonvoyage-perf01-rollback-probe.timer',
                            '--property=LoadState'):
                    return 'LoadState=loaded'
                return ''

            def service(name, keys):
                if name == 'irqbalance.service':
                    return {'ActiveState': 'active'}
                return {'ActiveState': 'active', 'SubState': 'running',
                        'DropInPaths': '', 'FragmentPath': str(vm.UNIT),
                        'MainPID': '9001', 'AllowedCPUs': '',
                        'MemoryHigh': 'infinity', 'MemoryMax': 'infinity'}

            with patch.object(vm, 'ROOT', root), patch.object(vm, 'RUNTIME', runtime), \
                 patch.object(vm, 'CONTROLS', controls), patch.object(vm, 'AIO_MAX', aio), \
                 patch.object(vm, 'BOOT_ID', boot), patch.object(vm, 'UNIT', unit), \
                 patch.object(vm, 'verify_running_command',
                              return_value={'loaded_argv': [
                                  '/usr/bin/bonvoyage-dataplane', '--smp', '1'],
                                  'process_argv': [
                                  '/usr/bin/bonvoyage-dataplane', '--smp', '1']}), \
                 patch.object(vm, 'wait_running_command', return_value=(
                     {'MainPID': '9001'}, {'loaded_argv': [
                         '/usr/bin/bonvoyage-dataplane', '--smp', '1'],
                         'process_argv': [
                         '/usr/bin/bonvoyage-dataplane', '--smp', '1']})), \
                 patch.object(vm, 'run', command), \
                 patch.object(vm, 'service', service), patch.object(vm, 'readiness'), \
                 patch.object(vm, 'irq_state', return_value={'affinity': {'70': '9'}}):
                result = vm.restore_locked('probe')
            self.assertEqual(result['status'], 'restored')
            self.assertEqual(aio.read_text().strip(), '65536')
            self.assertFalse(runtime.exists())
            self.assertIn(('systemctl', 'restart', 'bonvoyage.service'), calls)
            self.assertIn(('systemctl', 'stop', 'bonvoyage-perf01-rollback-probe.timer'), calls)

    def test_restore_refuses_foreign_control_without_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root, runtime, controls, aio, boot = self.fixture(directory, foreign=True)
            with patch.object(vm, 'ROOT', root), patch.object(vm, 'RUNTIME', runtime), \
                 patch.object(vm, 'CONTROLS', controls), patch.object(vm, 'AIO_MAX', aio), \
                 patch.object(vm, 'BOOT_ID', boot):
                with self.assertRaisesRegex(RuntimeError, 'foreign runtime file'):
                    vm.restore_locked('probe')
            self.assertTrue(all(path.exists() for path in controls.values()))
            self.assertEqual(aio.read_text().strip(), '524288')

    def test_atomic_state_rewrite_ignores_abandoned_temporary_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'state.json'
            path.with_name('state.json.old-crash').write_text('partial')
            vm.write_json(path, {'status': 'prepared'})
            vm.write_json(path, {'status': 'active'})
            self.assertEqual(json.loads(path.read_text())['status'], 'active')

    def test_control_publication_is_complete_and_exclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'control.conf'
            vm.write_control(path, b'complete\n')
            self.assertEqual(path.read_bytes(), b'complete\n')
            self.assertEqual([p.name for p in path.parent.iterdir()], ['control.conf'])
            with self.assertRaisesRegex(RuntimeError, 'already exists'):
                vm.write_control(path, b'foreign\n')
            self.assertEqual(path.read_bytes(), b'complete\n')

    def test_timer_cancel_accepts_loaded_and_already_unloaded_units(self):
        calls = []

        def loaded(*args):
            calls.append(args)
            if args[-1] == '--property=LoadState':
                return 'LoadState=loaded'
            return ''

        with patch.object(vm, 'run', loaded):
            vm.cancel_timer('probe')
        self.assertEqual(calls[-1],
                         ('systemctl', 'stop',
                          'bonvoyage-perf01-rollback-probe.timer'))
        with patch.object(vm, 'run', return_value='LoadState=not-found') as command:
            vm.cancel_timer('probe')
        command.assert_called_once_with(
            'systemctl', 'show', 'bonvoyage-perf01-rollback-probe.timer',
            '--property=LoadState')

    def test_timer_cancel_rejects_ambiguous_unit_state(self):
        with patch.object(vm, 'run', return_value='LoadState=error'):
            with self.assertRaisesRegex(RuntimeError, 'unknown load state'):
                vm.cancel_timer('probe')

    def test_running_command_requires_loaded_unit_executable_and_process_argv(self):
        expected = ['/usr/bin/bonvoyage-dataplane', '--smp', '24']
        with patch.object(vm, 'loaded_exec_argv', return_value=expected), \
             patch.object(vm.Path, 'resolve', return_value=vm.BINARY.resolve()), \
             patch.object(vm, 'file_digest', return_value='a' * 64), \
             patch.object(vm, 'argv', return_value=expected):
            result = vm.verify_running_command('42', expected, 'a' * 64)
        self.assertEqual(result['loaded_argv'], expected)
        self.assertEqual(result['process_argv'], expected)

    def test_running_command_waits_for_systemd_executor_to_exec_gateway(self):
        expected = ['/usr/bin/bonvoyage-dataplane', '--smp', '24']
        gateway = {'ActiveState': 'active', 'SubState': 'running', 'MainPID': '42',
                   'NRestarts': '0', 'FragmentPath': str(vm.UNIT),
                   'DropInPaths': '', 'NeedDaemonReload': 'no'}
        command = {'loaded_argv': expected, 'process_argv': expected}
        with patch.object(vm, 'service', return_value=gateway), \
             patch.object(vm, 'verify_running_command', side_effect=[
                 RuntimeError("actual_path='/usr/lib/systemd/systemd-executor'"), command]):
            observed_gateway, observed_command = vm.wait_running_command(
                expected, 'a' * 64, '1', timeout=1, poll=0)
        self.assertEqual(observed_gateway, gateway)
        self.assertEqual(observed_command, command)

    def test_apply_arms_recovery_before_first_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root = directory / 'record'
            root.mkdir()
            runtime = directory / 'runtime'
            aio = directory / 'aio'
            aio.write_text('65536\n')
            boot = directory / 'boot'
            boot.write_text('boot-1\n')
            controls = {'bonvoyage-resources.conf': runtime / 'resources.conf',
                        'bonvoyage-runtime.conf': runtime / 'runtime.conf'}
            contents = {name: name.encode() for name in controls}
            contents['irqbalance-exclusion.conf'] = (
                b'[Service]\nEnvironment="IRQBALANCE_BANNED_CPULIST=8-31"\n')
            plan = {'source_commit': 'a' * 40, 'binary_sha256': 'c' * 64,
                    'proposed_aio_max_nr': 524288}
            before = {'aio_max_nr': 65536, 'irqbalance': {'ActiveState': 'active'},
                      'gateway': {'MainPID': '5615'}}
            calls = []

            def command(*args):
                calls.append(args)
                if args[0] == 'systemd-run':
                    self.assertFalse(runtime.exists())
                    self.assertEqual(aio.read_text().strip(), '65536')
                if args == ('systemctl', 'restart', 'bonvoyage.service'):
                    raise RuntimeError('injected restart failure')
                return ''

            with patch.object(vm, 'ROOT', root), patch.object(vm, 'RUNTIME', runtime), \
                 patch.object(vm, 'CONTROLS', controls), patch.object(vm, 'AIO_MAX', aio), \
                 patch.object(vm, 'BOOT_ID', boot), \
                 patch.object(vm.os, 'geteuid', return_value=0), \
                 patch.object(vm.sys, 'platform', 'linux'), \
                 patch.object(vm, 'run', command), \
                 patch.object(vm, 'service', side_effect=lambda name, keys:
                              {'MainPID': '5615', 'ActiveState': 'active'}), \
                 patch.object(vm, 'verify_bundle', return_value=(plan, contents)), \
                 patch.object(vm, 'capture_before', return_value=before), \
                 patch.object(vm, 'restore_locked') as restore:
                with self.assertRaisesRegex(RuntimeError, 'injected restart failure'):
                    vm.apply_locked('probe', directory, 'b' * 64, 'boot-1')
            self.assertEqual(calls[0][0], 'systemd-run')
            self.assertIn(('systemctl', 'stop', 'irqbalance.service'), calls)
            restore.assert_called_once_with('probe')
            self.assertEqual(json.loads((root / 'probe/state.json').read_text())['status'],
                             'applying')

    def test_campaign_apply_arms_recovery_before_runtime_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root = directory / 'record'
            root.mkdir()
            runtime = directory / 'runtime'
            aio = directory / 'aio'
            aio.write_text('65536\n')
            boot = directory / 'boot'
            boot.write_text('boot-1\n')
            controls = {'bonvoyage-resources.conf': runtime / 'resources.conf',
                        'bonvoyage-runtime.conf': runtime / 'runtime.conf'}
            contents = {name: name.encode() for name in controls}
            contents['irqbalance-exclusion.conf'] = (
                b'[Service]\nEnvironment="IRQBALANCE_BANNED_CPULIST=8-31"\n')
            runtime_root = '/run/bonvoyage-perf06/policy-' + 'a' * 16
            plan = {'source_commit': 'b' * 40, 'binary_sha256': 'c' * 64,
                    'proposed_aio_max_nr': 524288,
                    'runtime_artifacts': {'root': runtime_root,
                                          'plan_id': 'a' * 64}}
            before = {'aio_max_nr': 65536,
                      'irqbalance': {'ActiveState': 'active'},
                      'gateway': {'MainPID': '5615'}}
            expectation = {'root': runtime_root, 'profile_id': 'P5-B02',
                           'plan_id': 'a' * 64,
                           'manifest_sha256': 'd' * 64, 'files': {}}
            calls = []

            def command(*args):
                calls.append(args)
                if args == ('systemctl', 'restart', 'bonvoyage.service'):
                    raise RuntimeError('injected restart failure')
                return ''

            def stage(*args):
                self.assertTrue(calls and calls[0][0] == 'systemd-run')
                calls.append(('stage-runtime',))
                return expectation

            with patch.object(vm, 'ROOT', root), patch.object(vm, 'RUNTIME', runtime), \
                 patch.object(vm, 'CONTROLS', controls), patch.object(vm, 'AIO_MAX', aio), \
                 patch.object(vm, 'BOOT_ID', boot), \
                 patch.object(vm.os, 'geteuid', return_value=0), \
                 patch.object(vm.sys, 'platform', 'linux'), \
                 patch.object(vm, 'run', side_effect=command), \
                 patch.object(vm, 'service', return_value={
                     'MainPID': '5615', 'ActiveState': 'active'}), \
                 patch.object(vm, 'verify_bundle', return_value=(plan, contents)), \
                 patch.object(vm, 'runtime_expectation', return_value=expectation), \
                 patch.object(vm, 'stage_runtime', side_effect=stage), \
                 patch.object(vm, 'capture_before', return_value=before), \
                 patch.object(vm, 'restore_locked') as restore:
                with self.assertRaisesRegex(RuntimeError,
                                            'injected restart failure'):
                    vm.apply_locked('probe', directory, 'e' * 64, 'boot-1',
                                    runtime_directory=directory,
                                    runtime_manifest_sha='d' * 64)
            self.assertEqual(calls[0][0], 'systemd-run')
            self.assertIn(('stage-runtime',), calls)
            restore.assert_called_once_with('probe')

    def test_static_apply_binds_effective_irq_affinity(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root = directory / 'record'
            root.mkdir()
            runtime = directory / 'runtime'
            aio = directory / 'aio'
            aio.write_text('65536\n')
            boot = directory / 'boot'
            boot.write_text('boot-1\n')
            controls = {'bonvoyage-resources.conf': runtime / 'resources.conf',
                        'bonvoyage-runtime.conf': runtime / 'runtime.conf'}
            contents = {name: name.encode() for name in controls}
            contents['irqbalance-exclusion.conf'] = (
                b'[Service]\nEnvironment="IRQBALANCE_BANNED_CPULIST=8-31"\n')
            labels = {'70': 'ena-mgmnt@pci:0000:27:00.0',
                      **{str(71 + index): f'enp39s0-Tx-Rx-{index}'
                         for index in range(8)}}
            before = {'aio_max_nr': 65536,
                      'irqbalance': {'ActiveState': 'active'},
                      'gateway': {'MainPID': '5615'},
                      'nic': {'interface': 'enp39s0', 'queues': 8,
                              'labels': labels,
                              'affinity': {irq: '31' for irq in labels}}}
            plan = {'source_commit': 'a' * 40, 'binary_sha256': 'c' * 64,
                    'proposed_aio_max_nr': 524288, 'irq_cpus': '0-7'}
            expected = {'70': '0', **{str(71 + index): str(index)
                                      for index in range(8)}}
            with patch.object(vm, 'ROOT', root), patch.object(vm, 'RUNTIME', runtime), \
                 patch.object(vm, 'CONTROLS', controls), patch.object(vm, 'AIO_MAX', aio), \
                 patch.object(vm, 'BOOT_ID', boot), \
                 patch.object(vm.os, 'geteuid', return_value=0), \
                 patch.object(vm.sys, 'platform', 'linux'), \
                 patch.object(vm, 'run', return_value=''), \
                 patch.object(vm, 'service', return_value={
                     'MainPID': '5615', 'ActiveState': 'active'}), \
                 patch.object(vm, 'verify_bundle', return_value=(plan, contents)), \
                 patch.object(vm, 'capture_before', return_value=before), \
                 patch.object(vm, 'verify_active', return_value={'gateway': 'active'}), \
                 patch.object(vm, 'apply_irq_affinity', return_value=expected) as apply_irq, \
                 patch.object(vm, 'cancel_timer'):
                result = vm.apply_locked('probe', directory, 'b' * 64, 'boot-1',
                                         'static-ena')
            apply_irq.assert_called_once_with(expected)
            self.assertEqual(result['profile'], 'static-ena')
            self.assertEqual(result['expected_irq_affinity'], expected)

    def test_active_exclusion_apply_publishes_runtime_dropin_and_restarts_daemon(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root = directory / 'record'
            root.mkdir()
            runtime = directory / 'gateway-runtime'
            irq_control = directory / 'irqbalance-runtime' / 'exclusion.conf'
            aio = directory / 'aio'
            aio.write_text('65536\n')
            boot = directory / 'boot'
            boot.write_text('boot-1\n')
            controls = {'bonvoyage-resources.conf': runtime / 'resources.conf',
                        'bonvoyage-runtime.conf': runtime / 'runtime.conf'}
            contents = {name: name.encode() for name in controls}
            exclusion = b'[Service]\nEnvironment="IRQBALANCE_BANNED_CPULIST=8-31"\n'
            contents['irqbalance-exclusion.conf'] = exclusion
            plan = {'source_commit': 'a' * 40, 'binary_sha256': 'c' * 64,
                    'proposed_aio_max_nr': 524288, 'irq_cpus': '0-1'}
            before = {'aio_max_nr': 65536, 'irqbalance': {
                          'ActiveState': 'active', 'DropInPaths': ''},
                      'gateway': {'MainPID': '5615'},
                      'nic': {'interface': 'enp39s0', 'queues': 2,
                              'labels': {
                                  '70': 'ena-mgmnt@pci:0000:27:00.0',
                                  '71': 'enp39s0-Tx-Rx-0',
                                  '72': 'enp39s0-Tx-Rx-1'}}}
            seeded = {'70': '0', '71': '0', '72': '1'}
            calls = []

            def command(*args):
                calls.append(args)
                return ''

            def seed_irq(mapping):
                calls.append(('apply_irq_affinity', mapping))
                return mapping

            with patch.object(vm, 'ROOT', root), patch.object(vm, 'RUNTIME', runtime), \
                 patch.object(vm, 'IRQBALANCE_RUNTIME', irq_control), \
                 patch.object(vm, 'CONTROLS', controls), patch.object(vm, 'AIO_MAX', aio), \
                 patch.object(vm, 'BOOT_ID', boot), \
                 patch.object(vm.os, 'geteuid', return_value=0), \
                 patch.object(vm.sys, 'platform', 'linux'), \
                 patch.object(vm, 'run', side_effect=command), \
                 patch.object(vm, 'service', return_value={
                     'MainPID': '5615', 'ActiveState': 'active'}), \
                 patch.object(vm, 'verify_bundle', return_value=(plan, contents)), \
                 patch.object(vm, 'capture_before', return_value=before), \
                 patch.object(vm, 'verify_active', return_value={'gateway': 'active'}), \
                 patch.object(vm, 'apply_irq_affinity', side_effect=seed_irq) as apply_irq, \
                 patch.object(vm, 'cancel_timer'):
                result = vm.apply_locked('probe', directory, 'b' * 64, 'boot-1',
                                         'irqbalance-active-exclusion')
            self.assertEqual(irq_control.read_bytes(), exclusion)
            self.assertIn(('systemctl', 'stop', 'irqbalance.service'), calls)
            self.assertIn(('systemctl', 'start', 'irqbalance.service'), calls)
            self.assertNotIn(('systemctl', 'restart', 'irqbalance.service'), calls)
            apply_irq.assert_called_once_with(seeded)
            self.assertLess(calls.index(('systemctl', 'stop', 'irqbalance.service')),
                            calls.index(('apply_irq_affinity', seeded)))
            self.assertLess(calls.index(('apply_irq_affinity', seeded)),
                            calls.index(('systemctl', 'start', 'irqbalance.service')))
            self.assertEqual(result['profile'], 'irqbalance-active-exclusion')
            self.assertEqual(result['seeded_irq_affinity'], seeded)

    def test_active_observed_apply_leaves_irqbalance_and_affinity_untouched(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root = directory / 'record'
            root.mkdir()
            runtime = directory / 'gateway-runtime'
            irq_control = directory / 'irqbalance-runtime' / 'exclusion.conf'
            aio = directory / 'aio'
            aio.write_text('65536\n')
            boot = directory / 'boot'
            boot.write_text('boot-1\n')
            controls = {'bonvoyage-resources.conf': runtime / 'resources.conf',
                        'bonvoyage-runtime.conf': runtime / 'runtime.conf'}
            contents = {name: name.encode() for name in controls}
            contents['irqbalance-exclusion.conf'] = (
                b'[Service]\nEnvironment="IRQBALANCE_BANNED_CPULIST=8-31"\n')
            plan = {'source_commit': 'a' * 40, 'binary_sha256': 'c' * 64,
                    'proposed_aio_max_nr': 524288, 'irq_cpus': '0-1'}
            before = {'aio_max_nr': 65536,
                      'irqbalance': {'ActiveState': 'active', 'DropInPaths': ''},
                      'gateway': {'MainPID': '5615'},
                      'nic': {'interface': 'enp39s0', 'queues': 2,
                              'labels': {
                                  '70': 'ena-mgmnt@pci:0000:27:00.0',
                                  '71': 'enp39s0-Tx-Rx-0',
                                  '72': 'enp39s0-Tx-Rx-1'}}}
            calls = []

            def command(*args):
                calls.append(args)
                return ''

            with patch.object(vm, 'ROOT', root), patch.object(vm, 'RUNTIME', runtime), \
                 patch.object(vm, 'IRQBALANCE_RUNTIME', irq_control), \
                 patch.object(vm, 'CONTROLS', controls), patch.object(vm, 'AIO_MAX', aio), \
                 patch.object(vm, 'BOOT_ID', boot), \
                 patch.object(vm.os, 'geteuid', return_value=0), \
                 patch.object(vm.sys, 'platform', 'linux'), \
                 patch.object(vm, 'run', side_effect=command), \
                 patch.object(vm, 'service', return_value={
                     'MainPID': '5615', 'ActiveState': 'active'}), \
                 patch.object(vm, 'verify_bundle', return_value=(plan, contents)), \
                 patch.object(vm, 'capture_before', return_value=before), \
                 patch.object(vm, 'verify_active', return_value={'gateway': 'active'}), \
                 patch.object(vm, 'apply_irq_affinity') as apply_irq, \
                 patch.object(vm, 'cancel_timer'):
                result = vm.apply_locked('probe', directory, 'b' * 64, 'boot-1',
                                         'irqbalance-active-observed')
            self.assertFalse(irq_control.exists())
            self.assertNotIn(('systemctl', 'stop', 'irqbalance.service'), calls)
            self.assertNotIn(('systemctl', 'start', 'irqbalance.service'), calls)
            apply_irq.assert_not_called()
            self.assertEqual(result['profile'], 'irqbalance-active-observed')

    def test_active_exclusion_restore_removes_dropin_and_restores_irqbalance(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root, runtime, controls, aio, boot = self.fixture(directory)
            attempt = root / 'probe'
            state = json.loads((attempt / 'state.json').read_text())
            state['profile'] = 'irqbalance-active-exclusion'
            exclusion = b'[Service]\nEnvironment="IRQBALANCE_BANNED_CPULIST=8-31"\n'
            state['irqbalance_control_sha256'] = vm.digest(exclusion)
            state['before']['irqbalance']['DropInPaths'] = ''
            vm.write_json(attempt / 'state.json', state)
            irq_control = directory / 'irqbalance-runtime' / 'exclusion.conf'
            irq_control.parent.mkdir()
            irq_control.write_bytes(exclusion)
            unit = directory / 'bonvoyage.service'
            unit.write_text('ExecStart=/usr/bin/bonvoyage-dataplane --smp 1\n')
            calls = []

            def command(*args):
                calls.append(args)
                if args == ('systemctl', 'show',
                            'bonvoyage-perf01-rollback-probe.timer',
                            '--property=LoadState'):
                    return 'LoadState=loaded'
                return ''

            def service(name, keys):
                if name == 'irqbalance.service':
                    return {'ActiveState': 'active', 'DropInPaths': ''}
                return {'ActiveState': 'active', 'SubState': 'running',
                        'DropInPaths': '', 'FragmentPath': str(vm.UNIT),
                        'MainPID': '9001', 'AllowedCPUs': '',
                        'MemoryHigh': 'infinity', 'MemoryMax': 'infinity'}

            command_record = {'loaded_argv': [
                '/usr/bin/bonvoyage-dataplane', '--smp', '1'],
                'process_argv': ['/usr/bin/bonvoyage-dataplane', '--smp', '1']}
            with patch.object(vm, 'ROOT', root), patch.object(vm, 'RUNTIME', runtime), \
                 patch.object(vm, 'IRQBALANCE_RUNTIME', irq_control), \
                 patch.object(vm, 'CONTROLS', controls), patch.object(vm, 'AIO_MAX', aio), \
                 patch.object(vm, 'BOOT_ID', boot), patch.object(vm, 'UNIT', unit), \
                 patch.object(vm, 'wait_running_command', return_value=(
                     {'MainPID': '9001'}, command_record)), \
                 patch.object(vm, 'run', side_effect=command), \
                 patch.object(vm, 'service', side_effect=service), \
                 patch.object(vm, 'readiness'), \
                 patch.object(vm, 'irq_state', return_value={'affinity': {'70': '9'}}):
                result = vm.restore_locked('probe')
            self.assertEqual(result['status'], 'restored')
            self.assertFalse(irq_control.exists())
            self.assertIn(('systemctl', 'restart', 'irqbalance.service'), calls)


if __name__ == '__main__':
    unittest.main()
