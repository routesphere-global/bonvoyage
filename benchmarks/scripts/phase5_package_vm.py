#!/usr/bin/env python3
"""Lab-only, runtime-scoped activation of a verified BonVoyage .deb plan."""

import argparse
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from urllib.request import Request, urlopen


ROOT = Path('/run/bonvoyage-perf01')
RUNTIME = Path('/run/systemd/system/bonvoyage.service.d')
IRQBALANCE_RUNTIME = Path(
    '/run/systemd/system/irqbalance.service.d/30-perf01-exclusion.conf')
UNIT = Path('/usr/lib/systemd/system/bonvoyage.service')
BINARY = Path('/usr/bin/bonvoyage-dataplane')
AIO_MAX = Path('/proc/sys/fs/aio-max-nr')
BOOT_ID = Path('/proc/sys/kernel/random/boot_id')
IRQ_ROOT = Path('/proc/irq')
FILES = ('aio-capacity.conf', 'bonvoyage-resources.conf',
         'bonvoyage-runtime.conf', 'irqbalance-exclusion.conf', 'plan.json')
CONTROLS = {
    'bonvoyage-resources.conf': RUNTIME / '20-perf01-resources.conf',
    'bonvoyage-runtime.conf': RUNTIME / '30-perf01-runtime.conf',
}
SHA = re.compile(r'^[0-9a-f]{64}$')
ATTEMPT = re.compile(r'^[a-z0-9][a-z0-9-]{0,31}$')
CAMPAIGN_ROOT = re.compile(
    r'^/run/bonvoyage-perf06/[a-z0-9][a-z0-9-]{0,63}$')
CAMPAIGN_PARENT = Path('/run/bonvoyage-perf06')
RUNTIME_FILES = (
    'active.pb', 'hosts', 'runtime.json', 'secrets/ca.pem',
    'secrets/phase5-policy-api-keys.txt',
    'secrets/phase5-policy-jwks.json', 'secrets/server-chain.pem',
    'secrets/server-key.pem')
RUNTIME_PROFILE = re.compile(r'^P5-(?:B02|C0[0-5])$')
ACTIVE_IRQ_PROFILES = frozenset(
    ('irqbalance-active-exclusion', 'irqbalance-active-observed'))
SUPPORTED_IRQ_PROFILES = frozenset(
    ('irqbalance-off-unpinned', 'static-ena', *ACTIVE_IRQ_PROFILES))


def ensure(ok, message):
    if not ok:
        raise RuntimeError(message)


def run(*argv):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=30,
                            check=False)
    ensure(result.returncode == 0, f'{argv[0]} {argv[1:]} failed: {result.stderr.strip()}')
    return result.stdout.strip()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    value = hashlib.sha256()
    with open(path, 'rb') as source:
        for chunk in iter(lambda: source.read(1048576), b''):
            value.update(chunk)
    return value.hexdigest()


def regular_bytes(path, limit=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        ensure(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= limit,
               f'unsafe or oversized file: {path}')
        chunks = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1048576))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b''.join(chunks)
        ensure(len(data) <= limit, f'oversized file: {path}')
        ensure(len(data) == st.st_size, f'incomplete file read: {path}')
        return data
    finally:
        os.close(fd)


def verify_bundle(directory, manifest_sha):
    ensure(SHA.fullmatch(manifest_sha), 'manifest SHA-256 invalid')
    ensure(directory.is_dir() and not directory.is_symlink(), 'bundle directory invalid')
    names = sorted(path.name for path in directory.iterdir())
    ensure(names == sorted((*FILES, 'checksums.sha256')), 'bundle membership changed')
    contents = {name: regular_bytes(directory / name) for name in FILES}
    manifest = regular_bytes(directory / 'checksums.sha256')
    ensure(digest(manifest) == manifest_sha, 'bundle manifest identity changed')
    expected = ''.join(f'{digest(contents[name])}  {name}\n' for name in sorted(FILES))
    ensure(manifest == expected.encode(), 'bundle checksums failed')
    plan = json.loads(contents['plan.json'])
    ensure(plan['schema_version'] == 1 and
           plan['evidence_class'] == 'shared-vm-placement-plan' and
           plan['source_dirty'] is False and
           plan['measurement_authorized'] is False and
           plan['expected_fragment_path'] == str(UNIT) and
           plan['install_targets']['bonvoyage-resources.conf'] ==
           '/etc/systemd/system/bonvoyage.service.d/20-perf01-resources.conf' and
           plan['install_targets']['bonvoyage-runtime.conf'] ==
           '/etc/systemd/system/bonvoyage.service.d/30-perf01-runtime.conf',
           'bundle plan is outside the reviewed package contract')
    ensure(SHA.fullmatch(plan['binary_sha256']) and
           SHA.fullmatch(plan['package_unit_sha256']) and
           plan['network_iocbs_per_shard'] in (10000, 15000),
           'bundle package or runtime identity invalid')
    runtime = plan.get('runtime_artifacts')
    if runtime is not None:
        ensure(set(runtime) == {'root', 'plan_id', 'snapshot_file',
                                'secrets_directory', 'hosts_file'} and
               CAMPAIGN_ROOT.fullmatch(runtime['root']) and
               SHA.fullmatch(runtime['plan_id']) and
               runtime['root'] == '/run/bonvoyage-perf06/policy-' +
               runtime['plan_id'][:16] and
               runtime['snapshot_file'] == runtime['root'] + '/active.pb' and
               runtime['secrets_directory'] == runtime['root'] + '/secrets' and
               runtime['hosts_file'] == runtime['root'] + '/hosts',
               'campaign runtime artifacts are outside the reviewed /run root')
        runtime_control = contents['bonvoyage-runtime.conf'].decode()
        ensure(f'--snapshot {runtime["snapshot_file"]}' in runtime_control and
               f'--secrets-directory {runtime["secrets_directory"]}' in
               runtime_control and
               f'BindReadOnlyPaths={runtime["hosts_file"]}:'
               '/etc/hosts:norbind' in runtime_control,
               'campaign runtime controls differ from the reviewed paths')
    ensure(all(plan['file_sha256'].get(name) == digest(contents[name])
               for name in FILES if name != 'plan.json'),
           'plan file digest differs from bundle')
    return plan, contents


def regular_tree_files(directory):
    ensure(directory.is_dir() and not directory.is_symlink(),
           'runtime bundle directory invalid')
    names = []
    for path in sorted(directory.rglob('*')):
        ensure(not path.is_symlink(), 'runtime bundle contains a symlink')
        if path.is_dir():
            continue
        relative = path.relative_to(directory).as_posix()
        st = path.stat()
        ensure(stat.S_ISREG(st.st_mode) and st.st_nlink == 1,
               f'unsafe runtime bundle member: {relative}')
        names.append(relative)
    return names


def verify_runtime_bundle(directory, manifest_sha, plan):
    ensure(SHA.fullmatch(manifest_sha), 'runtime manifest SHA-256 invalid')
    names = regular_tree_files(directory)
    expected_names = sorted((*RUNTIME_FILES, 'checksums.sha256'))
    ensure(names == expected_names, 'runtime bundle membership changed')
    contents = {name: regular_bytes(directory / name, 16 * 1024 * 1024)
                for name in RUNTIME_FILES}
    manifest = regular_bytes(directory / 'checksums.sha256', 1024 * 1024)
    ensure(digest(manifest) == manifest_sha,
           'runtime bundle manifest identity changed')
    expected_manifest = ''.join(
        f'{digest(contents[name])}  {name}\n' for name in sorted(RUNTIME_FILES))
    ensure(manifest == expected_manifest.encode(),
           'runtime bundle checksums failed')
    metadata = json.loads(contents['runtime.json'])
    ensure(set(metadata) == {'schema_version', 'evidence_class',
                             'source_commit', 'plan_id', 'profile_id',
                             'runtime_root', 'snapshot_sha256',
                             'campaign_manifest_sha256'},
           'runtime metadata fields changed')
    runtime = plan.get('runtime_artifacts')
    ensure(runtime is not None and metadata['schema_version'] == 1 and
           metadata['evidence_class'] == 'private-perf06-runtime-bundle' and
           metadata['source_commit'] == plan['source_commit'] and
           metadata['plan_id'] == runtime['plan_id'] and
           RUNTIME_PROFILE.fullmatch(metadata['profile_id']) and
           metadata['runtime_root'] == runtime['root'] and
           metadata['snapshot_sha256'] == digest(contents['active.pb']) and
           SHA.fullmatch(metadata['campaign_manifest_sha256']),
           'runtime metadata differs from the placement plan')
    return metadata, contents


def runtime_expectation(directory, manifest_sha, plan):
    metadata, contents = verify_runtime_bundle(directory, manifest_sha, plan)
    return {'root': metadata['runtime_root'], 'profile_id': metadata['profile_id'],
            'plan_id': metadata['plan_id'], 'manifest_sha256': manifest_sha,
            'files': {name: digest(contents[name]) for name in RUNTIME_FILES}}


def verify_runtime_expectation(expectation):
    root = Path(expectation['root'])
    ensure(root.parent == CAMPAIGN_PARENT and CAMPAIGN_ROOT.fullmatch(str(root)),
           'recorded runtime root is unsafe')
    names = regular_tree_files(root)
    ensure(names == sorted((*RUNTIME_FILES, 'checksums.sha256')),
           'staged runtime membership changed')
    for name, expected in expectation['files'].items():
        ensure(file_digest(root / name) == expected,
               f'staged runtime artifact changed: {name}')
    ensure(file_digest(root / 'checksums.sha256') ==
           expectation['manifest_sha256'],
           'staged runtime manifest changed')
    gid = grp.getgrnam('bonvoyage').gr_gid
    for directory in (root, root / 'secrets'):
        observed = directory.stat()
        ensure(observed.st_uid == os.geteuid() and observed.st_gid == gid and
               stat.S_IMODE(observed.st_mode) == 0o750,
               f'staged runtime directory permissions changed: {directory}')
    for name in (*RUNTIME_FILES, 'checksums.sha256'):
        observed = (root / name).stat()
        expected_mode = 0o644 if name == 'hosts' else 0o640
        ensure(observed.st_uid == os.geteuid() and observed.st_gid == gid and
               stat.S_IMODE(observed.st_mode) == expected_mode,
               f'staged runtime file permissions changed: {name}')


def write_runtime_file(target, content, mode, gid):
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_CLOEXEC | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as output:
            output.write(content)
            output.flush()
        os.fsync(fd)
        os.fchmod(fd, mode)
        os.fchown(fd, 0, gid)
        os.fsync(fd)
    finally:
        os.close(fd)


def stage_runtime(directory, manifest_sha, plan, record):
    metadata, contents = verify_runtime_bundle(directory, manifest_sha, plan)
    target = Path(metadata['runtime_root'])
    ensure(target.parent == CAMPAIGN_PARENT and not target.exists(),
           'campaign runtime root already exists or is unsafe')
    CAMPAIGN_PARENT.mkdir(mode=0o755, parents=True, exist_ok=True)
    parent_stat = CAMPAIGN_PARENT.lstat()
    ensure(stat.S_ISDIR(parent_stat.st_mode) and
           not CAMPAIGN_PARENT.is_symlink() and
           parent_stat.st_uid == os.geteuid() and
           parent_stat.st_mode & 0o022 == 0,
           'campaign runtime parent is unsafe')
    staging = record / 'runtime-staging'
    ensure(not staging.exists(), 'campaign runtime staging already exists')
    staging.mkdir(mode=0o750)
    gid = grp.getgrnam('bonvoyage').gr_gid
    os.chown(staging, 0, gid)
    secrets = staging / 'secrets'
    secrets.mkdir(mode=0o750)
    os.chown(secrets, 0, gid)
    for name in RUNTIME_FILES:
        destination = staging / name
        if name.startswith('secrets/'):
            destination.parent.mkdir(mode=0o750, exist_ok=True)
        mode = 0o644 if name == 'hosts' else 0o640
        write_runtime_file(destination, contents[name], mode, gid)
    write_runtime_file(staging / 'checksums.sha256',
                       regular_bytes(directory / 'checksums.sha256',
                                     1024 * 1024), 0o640, gid)
    os.replace(staging, target)
    parent = os.open(CAMPAIGN_PARENT, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    expectation = runtime_expectation(directory, manifest_sha, plan)
    verify_runtime_expectation(expectation)
    return expectation


def verify_partial_staging(record):
    staging = record / 'runtime-staging'
    if not staging.exists() and not staging.is_symlink():
        return False
    ensure(staging.is_dir() and not staging.is_symlink(),
           'campaign runtime staging path is unsafe')
    for path in staging.rglob('*'):
        ensure(not path.is_symlink(),
               'campaign runtime staging contains a symlink')
        if path.is_file():
            st = path.stat()
            ensure(stat.S_ISREG(st.st_mode) and st.st_nlink == 1,
                   'campaign runtime staging contains an unsafe file')
    return True


def runtime_before_restore(state, record):
    expectation = state.get('runtime')
    if expectation is None:
        return {'target_exists': False, 'staging_exists': False}
    target = Path(expectation['root'])
    ensure(not target.is_symlink(), 'campaign runtime root became a symlink')
    target_exists = target.exists()
    if target_exists:
        verify_runtime_expectation(expectation)
    ensure(state['status'] != 'active' or target_exists,
           'active campaign runtime root disappeared')
    return {'target_exists': target_exists,
            'staging_exists': verify_partial_staging(record)}


def remove_runtime(expectation, record, observed):
    if observed['target_exists']:
        verify_runtime_expectation(expectation)
        shutil.rmtree(expectation['root'])
    staging = record / 'runtime-staging'
    if observed['staging_exists']:
        verify_partial_staging(record)
        shutil.rmtree(staging)
    if CAMPAIGN_PARENT.exists() and not any(CAMPAIGN_PARENT.iterdir()):
        CAMPAIGN_PARENT.rmdir()


def service(name, keys):
    output = run('systemctl', 'show', name, '--all', f'--property={",".join(keys)}')
    pairs = [line.split('=', 1) for line in output.splitlines()]
    ensure(all(len(pair) == 2 for pair in pairs), 'invalid systemd properties')
    props = dict(pairs)
    ensure(len(props) == len(pairs) and all(key in props for key in keys),
           'missing or duplicate systemd property')
    return props


def argv(pid):
    return [part.decode() for part in Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
            if part]


def loaded_exec_argv():
    value = run('systemctl', 'show', 'bonvoyage.service', '--property=ExecStart', '--value')
    match = re.fullmatch(r'\{ path=([^ ;]+) ; argv\[\]=(.*?) ; ignore_errors=.*', value)
    ensure(match is not None, 'loaded ExecStart format is unsupported')
    result = shlex.split(match.group(2))
    ensure(result and result[0] == match.group(1), 'loaded ExecStart path and argv differ')
    return result


def verify_running_command(pid, expected_argv, binary_sha):
    loaded_argv = loaded_exec_argv()
    ensure(loaded_argv == expected_argv,
           f'loaded argv mismatch: expected={expected_argv!r}, actual={loaded_argv!r}')
    executable = Path(f'/proc/{pid}/exe')
    resolved_executable = executable.resolve()
    resolved_binary = BINARY.resolve()
    executable_sha = file_digest(executable)
    ensure(resolved_executable == resolved_binary and executable_sha == binary_sha,
           f'running executable identity differs from plan: '
           f'expected_path={str(resolved_binary)!r}, '
           f'actual_path={str(resolved_executable)!r}, '
           f'expected_sha256={binary_sha!r}, actual_sha256={executable_sha!r}')
    process_argv = argv(pid)
    ensure(process_argv == expected_argv,
           f'process argv mismatch: expected={expected_argv!r}, actual={process_argv!r}')
    return {'loaded_argv': loaded_argv, 'process_argv': process_argv}


def wait_running_command(expected_argv, binary_sha, previous_pid, timeout=10, poll=0.1):
    deadline = time.monotonic() + timeout
    error = 'service did not expose a candidate process'
    while time.monotonic() < deadline:
        gateway = service('bonvoyage.service', ['ActiveState', 'SubState', 'MainPID',
            'NRestarts', 'FragmentPath', 'DropInPaths', 'NeedDaemonReload'])
        if (gateway['ActiveState'] == 'active' and gateway['SubState'] == 'running' and
                gateway['MainPID'] not in ('0', previous_pid)):
            try:
                return gateway, verify_running_command(gateway['MainPID'], expected_argv,
                                                       binary_sha)
            except (OSError, RuntimeError) as command_error:
                error = str(command_error)
        time.sleep(poll)
    raise RuntimeError(f'tuned process did not reach the reviewed command: {error}')


def irq_state():
    route = json.loads(run('ip', '-j', '-4', 'route', 'show', 'default'))
    ensure(len(route) == 1 and re.fullmatch(r'[A-Za-z0-9_.-]+', route[0]['dev']),
           'ambiguous default NIC')
    interface = route[0]['dev']
    channels = run('ethtool', '-l', interface).split('Current hardware settings:')
    ensure(len(channels) == 2, 'NIC channel observation incomplete')
    match = re.search(r'(?m)^Combined:\s*(\d+)$', channels[1])
    ensure(match is not None, 'NIC queue count unavailable')
    queues = int(match.group(1))
    irq_dir = Path('/sys/class/net') / interface / 'device/msi_irqs'
    irqs = sorted(int(p.name) for p in irq_dir.iterdir())
    labels = {}
    for line in Path('/proc/interrupts').read_text().splitlines():
        match = re.match(r'^\s*(\d+):', line)
        if match:
            labels[int(match.group(1))] = line.split()[-1]
    affinity = {str(irq): Path(f'/proc/irq/{irq}/effective_affinity_list')
                .read_text().strip() for irq in irqs}
    observed = [labels.get(irq, '') for irq in irqs]
    ensure(len(irqs) == queues + 1 and
           sum(bool(re.fullmatch(r'ena-mgmnt@pci:[0-9a-f:.]+', label))
               for label in observed) == 1 and
           sorted(label for label in observed if label.startswith(interface + '-Tx-Rx-')) ==
           sorted(f'{interface}-Tx-Rx-{index}' for index in range(queues)),
           'ENA management and queue IRQ identities incomplete')
    return {'interface': interface, 'queues': queues, 'affinity': affinity,
            'labels': {str(irq): labels[irq] for irq in irqs}}


def static_ena_affinity(nic, irq_spec):
    cpus = sorted(expand_cpus(irq_spec))
    ensure(len(cpus) == nic['queues'],
           'static ENA profile requires one planned CPU per queue')
    management = []
    queues = {}
    for irq, label in nic['labels'].items():
        if re.fullmatch(r'ena-mgmnt@pci:[0-9a-f:.]+', label):
            management.append(irq)
            continue
        match = re.fullmatch(re.escape(nic['interface']) + r'-Tx-Rx-(\d+)', label)
        ensure(match is not None, f'unrecognized ENA IRQ label: {label}')
        index = int(match.group(1))
        ensure(index not in queues and index < len(cpus), 'ENA queue index invalid')
        queues[index] = irq
    ensure(len(management) == 1 and sorted(queues) == list(range(len(cpus))),
           'ENA management and queue IRQ identities incomplete')
    mapping = {management[0]: str(cpus[0])}
    mapping.update({queues[index]: str(cpu) for index, cpu in enumerate(cpus)})
    return mapping


def apply_irq_affinity(mapping):
    ensure(mapping and all(re.fullmatch(r'\d+', irq) and
                           re.fullmatch(r'\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*', cpus)
                           for irq, cpus in mapping.items()),
           'IRQ affinity mapping invalid')
    for irq in sorted(mapping, key=int):
        (IRQ_ROOT / irq / 'smp_affinity_list').write_text(mapping[irq] + '\n')
    observed = irq_state()['affinity']
    ensure(all(observed.get(irq) == cpus for irq, cpus in mapping.items()),
           f'IRQ affinity did not converge: expected={mapping!r}, observed={observed!r}')
    return observed


def wait_irq_affinity_allowed(before_nic, allowed_spec, forbidden_spec,
                              timeout=60, poll=0.2, stable_samples=5):
    allowed = expand_cpus(allowed_spec)
    forbidden = expand_cpus(forbidden_spec)
    ensure(allowed.isdisjoint(forbidden), 'IRQ and gateway CPU sets overlap')
    ensure(stable_samples >= 1, 'IRQ stability sample count invalid')
    deadline = time.monotonic() + timeout
    observed = None
    stable = 0
    while time.monotonic() < deadline:
        observed = irq_state()
        if (observed['interface'] == before_nic['interface'] and
                observed['queues'] == before_nic['queues'] and
                observed['labels'] == before_nic['labels'] and
                all(expand_cpus(cpus).issubset(allowed) and
                    expand_cpus(cpus).isdisjoint(forbidden)
                    for cpus in observed['affinity'].values())):
            stable += 1
            if stable >= stable_samples:
                return observed
        else:
            stable = 0
        time.sleep(poll)
    raise RuntimeError(
        f'IRQ affinity did not converge inside allowed CPUs: '
        f'allowed={allowed_spec!r}, forbidden={forbidden_spec!r}, '
        f'observed={observed!r}')


def best_effort_restore_irq_affinity(mapping):
    errors = {}
    for irq in sorted(mapping, key=int):
        try:
            (IRQ_ROOT / irq / 'smp_affinity_list').write_text(mapping[irq] + '\n')
        except OSError as error:
            errors[irq] = str(error)
    observed = irq_state()['affinity']
    return {'requested': mapping, 'observed': observed, 'write_errors': errors,
            'converged': all(observed.get(irq) == cpus
                             for irq, cpus in mapping.items())}


def capture_before(plan, boot):
    ensure(BOOT_ID.read_text().strip() == boot, 'host boot changed')
    ensure(digest(regular_bytes(UNIT)) == plan['package_unit_sha256'],
           'package unit changed')
    ensure(file_digest(BINARY) == plan['binary_sha256'], 'package binary changed')
    ensure(Path('/sys/devices/system/cpu/online').read_text().strip() ==
           plan['online_cpus'], 'online CPUs changed')
    gateway = service('bonvoyage.service', ['ActiveState', 'SubState', 'MainPID',
        'NRestarts', 'FragmentPath', 'DropInPaths', 'NeedDaemonReload'])
    irq = service('irqbalance.service', ['ActiveState', 'DropInPaths'])
    nitro = service('aws-nitro-irqbalance.service', ['ActiveState'])
    ensure(gateway['ActiveState'] == 'active' and gateway['SubState'] == 'running' and
           gateway['NRestarts'] == '0' and gateway['FragmentPath'] == str(UNIT) and
           gateway['DropInPaths'] == '' and gateway['NeedDaemonReload'] == 'no' and
           irq['ActiveState'] == 'active' and irq['DropInPaths'] == '' and
           nitro['ActiveState'] == 'inactive', 'services differ from untuned package baseline')
    base = [line.removeprefix('ExecStart=') for line in UNIT.read_text().splitlines()
            if line.startswith('ExecStart=')]
    ensure(len(base) == 1, 'package unit must contain exactly one command')
    command = verify_running_command(gateway['MainPID'], shlex.split(base[0]),
                                     plan['binary_sha256'])
    ensure(not RUNTIME.exists() and all(not target.exists() for target in CONTROLS.values()),
           'runtime controls already present')
    aio_max = int(AIO_MAX.read_text())
    aio_nr = int(Path('/proc/sys/fs/aio-nr').read_text())
    ensure(aio_max == plan['current_aio_max_nr'] and aio_nr <= aio_max,
           'AIO baseline drifted')
    nic = irq_state()
    ensure(nic['queues'] == len(expand_cpus(plan['irq_cpus'])),
           'NIC queue count differs from plan')
    return {'boot_id': boot, 'gateway': gateway, 'command': command, 'irqbalance': irq,
            'nitro_irqbalance': nitro, 'aio_max_nr': aio_max, 'aio_nr': aio_nr,
            'nic': nic}


def expand_cpus(spec):
    ensure(re.fullmatch(r'\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*', spec), 'CPU set invalid')
    cpus = set()
    for part in spec.split(','):
        first, _, last = part.partition('-')
        start, end = int(first), int(last or first)
        ensure(start <= end and end - start < 4096, 'CPU range invalid')
        cpus.update(range(start, end + 1))
    ensure(cpus, 'CPU set empty')
    return cpus


def process_thread_affinity(pid):
    tasks = []
    for task in sorted(Path(f'/proc/{pid}/task').iterdir(), key=lambda path: int(path.name)):
        try:
            status = task.joinpath('status').read_text()
            name = task.joinpath('comm').read_text().strip()
        except FileNotFoundError:
            continue
        allowed = re.search(r'(?m)^Cpus_allowed_list:\s*([^\n]+)$', status)
        ensure(allowed is not None, f'task {task.name} has no CPU affinity')
        spec = allowed.group(1).strip()
        tasks.append({'tid': int(task.name), 'name': name, 'cpus': spec})
    ensure(tasks, 'gateway has no observable tasks')
    return tasks


def verify_thread_affinity(pid, expected_spec):
    expected = expand_cpus(expected_spec)
    tasks = process_thread_affinity(pid)
    observed = [expand_cpus(task['cpus']) for task in tasks]
    ensure(all(cpus.issubset(expected) for cpus in observed),
           f'gateway task escaped planned CPUs: tasks={tasks!r}')
    singleton_cpus = {next(iter(cpus)) for cpus in observed if len(cpus) == 1}
    ensure(singleton_cpus == expected,
           f'pinned gateway tasks do not cover planned CPUs: '
           f'expected={sorted(expected)!r}, singleton_cpus={sorted(singleton_cpus)!r}, '
           f'tasks={tasks!r}')
    return tasks


def write_json(path, value):
    data = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd, name = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as target:
            target.write(data)
            target.flush()
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def write_control(path, content, staging_dir=None):
    ensure(not path.exists(), 'runtime control already exists')
    fd, name = tempfile.mkstemp(prefix='.perf01-', dir=staging_dir or path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as target:
            target.write(content)
            target.flush()
        os.fsync(fd)
        os.fchmod(fd, 0o644)
    finally:
        os.close(fd)
    try:
        ensure(not path.exists(), 'runtime control appeared during staging')
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def readiness(runtime=None, timeout=10):
    if runtime is None:
        request = Request('http://127.0.0.1:8080/payload/256',
                          headers={'Host': 'api.example.test'})
        label = 'gateway readiness response'

        def valid(response):
            return response.status == 200 and len(response.read(257)) == 256
    else:
        ensure(re.fullmatch(r'P5-(?:B02|C0[0-5])', runtime['profile_id']),
               'campaign readiness profile is invalid')
        request = Request('http://127.0.0.1:9090/metrics')
        label = 'gateway metrics readiness response'

        def valid(response):
            return response.status == 200 and len(response.read(1)) == 1

    deadline = time.monotonic() + timeout
    last_error = None
    while True:
        try:
            remaining = max(0.1, deadline - time.monotonic())
            with urlopen(request, timeout=min(1, remaining)) as response:
                ensure(valid(response), f'{label} invalid')
                return
        except (OSError, RuntimeError) as error:
            last_error = error
        if time.monotonic() >= deadline:
            raise RuntimeError(f'{label} did not become ready: {last_error}')
        time.sleep(0.1)


def verify_active(plan, before, contents, profile, expected_irq_affinity=None,
                  runtime=None):
    runtime_lines = contents['bonvoyage-runtime.conf'].decode().splitlines()
    expected_argv = shlex.split([line.removeprefix('ExecStart=')
                                 for line in runtime_lines
                                 if line.startswith('ExecStart=/usr/bin/')][0])
    gateway, command = wait_running_command(expected_argv, plan['binary_sha256'],
                                            before['gateway']['MainPID'])
    expected_paths = {str(path) for path in CONTROLS.values()}
    ensure(gateway['NRestarts'] == '0' and gateway['FragmentPath'] == str(UNIT) and
           set(gateway['DropInPaths'].split()) == expected_paths and
           gateway['NeedDaemonReload'] == 'no', 'tuned service failed identity check')
    cgroup = Path('/sys/fs/cgroup/system.slice/bonvoyage.service')
    cpus = cgroup.joinpath('cpuset.cpus.effective').read_text().strip()
    ensure(expand_cpus(cpus) == expand_cpus(plan['gateway_cpus']),
           'effective gateway CPUs differ from plan')
    task_affinity = verify_thread_affinity(gateway['MainPID'], plan['gateway_cpus'])
    ensure(int(cgroup.joinpath('memory.high').read_text()) ==
           plan['memory_high_mib'] * 1048576 and
           int(cgroup.joinpath('memory.max').read_text()) ==
           plan['memory_max_mib'] * 1048576, 'effective memory limits differ')
    irq = service('irqbalance.service', ['ActiveState', 'DropInPaths'])
    ensure(int(AIO_MAX.read_text()) == plan['proposed_aio_max_nr'] and
           service('aws-nitro-irqbalance.service', ['ActiveState'])['ActiveState'] == 'inactive',
           'host AIO or Nitro IRQ service state differs from profile')
    if profile == 'irqbalance-active-exclusion':
        ensure(irq['ActiveState'] == 'active' and
               set(irq['DropInPaths'].split()) == {str(IRQBALANCE_RUNTIME)} and
               digest(regular_bytes(IRQBALANCE_RUNTIME)) ==
               digest(contents['irqbalance-exclusion.conf']),
               'active irqbalance exclusion control differs from profile')
        nic = wait_irq_affinity_allowed(before['nic'], plan['irq_cpus'],
                                        plan['gateway_cpus'])
    elif profile == 'irqbalance-active-observed':
        ensure(irq == before['irqbalance'] and irq['ActiveState'] == 'active' and
               not IRQBALANCE_RUNTIME.exists(),
               'observed irqbalance service changed from package baseline')
        nic = irq_state()
    else:
        ensure(irq['ActiveState'] == 'inactive' and irq['DropInPaths'] == '',
               'irqbalance service state differs from stopped profile')
        nic = irq_state()
    ensure(nic['interface'] == before['nic']['interface'] and
           nic['queues'] == before['nic']['queues'] and
           nic['labels'] == before['nic']['labels'], 'NIC identity changed')
    if expected_irq_affinity is not None:
        ensure(nic['affinity'] == expected_irq_affinity,
               'effective NIC IRQ affinity differs from static profile')
    readiness(runtime)
    time.sleep(2)
    expected_irq_state = ('active' if profile in ACTIVE_IRQ_PROFILES
                          else 'inactive')
    ensure(service('bonvoyage.service', ['MainPID'])['MainPID'] == gateway['MainPID'] and
           service('irqbalance.service', ['ActiveState'])['ActiveState'] ==
           expected_irq_state,
           'gateway or IRQ service did not remain stable')
    return {'gateway': gateway, 'command': command, 'task_affinity': task_affinity, 'nic': nic,
            'aio_max_nr': int(AIO_MAX.read_text())}


def cancel_timer(attempt):
    timer = f'bonvoyage-perf01-rollback-{attempt}.timer'
    load = run('systemctl', 'show', timer, '--property=LoadState')
    if load == 'LoadState=not-found':
        return
    ensure(load == 'LoadState=loaded', 'rollback timer has unknown load state')
    run('systemctl', 'stop', timer)


def restore_locked(attempt):
    record = ROOT / attempt
    state = json.loads(regular_bytes(record / 'state.json'))
    ensure(state['status'] in ('prepared', 'applying', 'active', 'restoring'),
           'attempt is not restorable')
    ensure(file_digest(Path(__file__)) == state['helper_sha256'] and
           file_digest(record / 'helper.py') == state['helper_sha256'],
           'restore helper identity changed')
    ensure(BOOT_ID.read_text().strip() == state['before']['boot_id'],
           'host rebooted; runtime controls require manual review')
    runtime_observed = runtime_before_restore(state, record)
    for name, target in CONTROLS.items():
        if target.exists():
            ensure(digest(regular_bytes(target)) == state['control_sha256'][name],
                   'foreign runtime control blocks restoration')
    if RUNTIME.exists():
        ensure(set(RUNTIME.iterdir()).issubset(set(CONTROLS.values())),
               'foreign runtime file blocks restoration')
    if IRQBALANCE_RUNTIME.exists():
        ensure(state.get('irqbalance_control_sha256') and
               digest(regular_bytes(IRQBALANCE_RUNTIME)) ==
               state['irqbalance_control_sha256'],
               'foreign irqbalance runtime control blocks restoration')
    aio = int(AIO_MAX.read_text())
    ensure(aio in (state['before']['aio_max_nr'], state['planned_aio_max_nr']),
           'foreign AIO change blocks restoration')
    previous_pid = service('bonvoyage.service', ['MainPID'])['MainPID']
    state['status'] = 'restoring'
    write_json(record / 'state.json', state)
    changed = False
    for target in CONTROLS.values():
        if target.exists():
            target.unlink()
            changed = True
    if RUNTIME.exists():
        RUNTIME.rmdir()
    irqbalance_changed = False
    if IRQBALANCE_RUNTIME.exists():
        IRQBALANCE_RUNTIME.unlink()
        IRQBALANCE_RUNTIME.parent.rmdir()
        irqbalance_changed = True
    if changed or irqbalance_changed:
        run('systemctl', 'daemon-reload')
    if changed:
        run('systemctl', 'restart', 'bonvoyage.service')
    if state.get('profile') == 'static-ena':
        state['restored_static_irq_affinity'] = best_effort_restore_irq_affinity(
            state['before']['nic']['affinity'])
        write_json(record / 'state.json', state)
    if state['before']['irqbalance']['ActiveState'] == 'active':
        run('systemctl', 'restart', 'irqbalance.service')
    if aio != state['before']['aio_max_nr']:
        AIO_MAX.write_text(str(state['before']['aio_max_nr']) + '\n')
    base = [line.removeprefix('ExecStart=') for line in UNIT.read_text().splitlines()
            if line.startswith('ExecStart=')]
    base_argv = shlex.split(base[0]) if len(base) == 1 else []
    command_error = None
    try:
        if changed:
            observed_gateway, command = wait_running_command(
                base_argv, state['binary_sha256'], previous_pid)
        else:
            observed_gateway = service('bonvoyage.service', ['MainPID'])
            command = verify_running_command(observed_gateway['MainPID'], base_argv,
                                             state['binary_sha256'])
    except Exception as error:
        observed_gateway = None
        command = None
        command_error = str(error)
    gateway = service('bonvoyage.service', ['ActiveState', 'SubState', 'DropInPaths',
        'FragmentPath', 'MainPID', 'AllowedCPUs', 'MemoryHigh', 'MemoryMax'])
    restored_irq = service('irqbalance.service', ['ActiveState', 'DropInPaths'])
    ensure(gateway['ActiveState'] == 'active' and gateway['SubState'] == 'running' and
           observed_gateway is not None and
           gateway['MainPID'] == observed_gateway['MainPID'] and
           gateway['DropInPaths'] == '' and gateway['FragmentPath'] == str(UNIT) and
           gateway['AllowedCPUs'] == '' and gateway['MemoryHigh'] == 'infinity' and
           gateway['MemoryMax'] == 'infinity' and len(base) == 1 and
           command is not None and
           int(AIO_MAX.read_text()) == state['before']['aio_max_nr'] and
           restored_irq == state['before']['irqbalance'],
           f'restored baseline failed verification: gateway={gateway!r}, '
           f'command_error={command_error!r}, '
           f'aio_max_nr={AIO_MAX.read_text().strip()}')
    readiness()
    if state.get('runtime') is not None:
        remove_runtime(state['runtime'], record, runtime_observed)
        state['runtime_removed'] = True
    state['status'] = 'restored'
    state['restored_gateway_pid'] = gateway['MainPID']
    state['restored_command'] = command
    state['restored_irq_affinity'] = irq_state()['affinity']
    write_json(record / 'state.json', state)
    cancel_timer(attempt)
    return state


def apply_locked(attempt, directory, manifest_sha, boot,
                 profile='irqbalance-off-unpinned', runtime_directory=None,
                 runtime_manifest_sha=None):
    ensure(os.geteuid() == 0 and sys.platform == 'linux', 'apply requires Linux root')
    ensure(profile in SUPPORTED_IRQ_PROFILES,
           'unsupported IRQ profile')
    ensure(not (ROOT / attempt).exists(), 'attempt already exists')
    ensure(not any(json.loads(regular_bytes(path / 'state.json'))['status'] != 'restored'
                   for path in ROOT.iterdir() if path.is_dir()),
           'another activation requires restoration')
    plan, contents = verify_bundle(directory, manifest_sha)
    if plan.get('runtime_artifacts') is not None:
        ensure(runtime_directory is not None and runtime_manifest_sha is not None,
               'campaign placement requires its runtime bundle')
        runtime = runtime_expectation(runtime_directory,
                                      runtime_manifest_sha, plan)
    else:
        ensure(runtime_directory is None and runtime_manifest_sha is None,
               'ordinary placement cannot accept a runtime bundle')
        runtime = None
    before = capture_before(plan, boot)
    record = ROOT / attempt
    record.mkdir(mode=0o700)
    shutil.copyfile(__file__, record / 'helper.py')
    os.chmod(record / 'helper.py', 0o700)
    state = {'schema_version': 1, 'status': 'prepared', 'profile': profile,
             'manifest_sha256': manifest_sha, 'plan_source_commit': plan['source_commit'],
             'binary_sha256': plan['binary_sha256'],
             'helper_sha256': file_digest(record / 'helper.py'),
             'control_sha256': {name: digest(contents[name]) for name in CONTROLS},
             'irqbalance_control_sha256':
             digest(contents['irqbalance-exclusion.conf']),
             'planned_aio_max_nr': plan['proposed_aio_max_nr'],
             'runtime': runtime, 'before': before}
    write_json(record / 'state.json', state)
    run('systemd-run', f'--unit=bonvoyage-perf01-rollback-{attempt}',
        '--on-active=15m', '/usr/bin/python3', str(record / 'helper.py'),
        'restore', '--attempt', attempt)
    try:
        ensure(BOOT_ID.read_text().strip() == boot and
               service('bonvoyage.service', ['MainPID'])['MainPID'] ==
               before['gateway']['MainPID'] and
               service('irqbalance.service', ['ActiveState'])['ActiveState'] == 'active',
               'service or boot changed before mutation')
        state['status'] = 'applying'
        write_json(record / 'state.json', state)
        if runtime is not None:
            staged = stage_runtime(runtime_directory, runtime_manifest_sha,
                                   plan, record)
            ensure(staged == runtime,
                   'staged runtime identity differs from prepared state')
        RUNTIME.mkdir(mode=0o755)
        for name, target in CONTROLS.items():
            write_control(target, contents[name], record)
        if profile == 'irqbalance-active-exclusion':
            ensure(not IRQBALANCE_RUNTIME.parent.exists(),
                   'irqbalance runtime drop-in directory already exists')
            IRQBALANCE_RUNTIME.parent.mkdir(mode=0o755)
            write_control(IRQBALANCE_RUNTIME,
                          contents['irqbalance-exclusion.conf'], record)
        AIO_MAX.write_text(str(plan['proposed_aio_max_nr']) + '\n')
        if profile != 'irqbalance-active-observed':
            run('systemctl', 'stop', 'irqbalance.service')
        run('systemctl', 'daemon-reload')
        run('systemctl', 'restart', 'bonvoyage.service')
        if profile == 'irqbalance-active-exclusion':
            # Controllable hosts can seed ENA vectors before the daemon resumes.
            # Platforms that do not honor effective affinity use the observed
            # profile and make no disjoint-placement claim.
            seeded_irq_affinity = static_ena_affinity(
                before['nic'], plan['irq_cpus'])
            state['seeded_irq_affinity'] = seeded_irq_affinity
            write_json(record / 'state.json', state)
            apply_irq_affinity(seeded_irq_affinity)
            run('systemctl', 'start', 'irqbalance.service')
        expected_irq_affinity = None
        if profile == 'static-ena':
            expected_irq_affinity = static_ena_affinity(before['nic'], plan['irq_cpus'])
            state['expected_irq_affinity'] = expected_irq_affinity
            write_json(record / 'state.json', state)
            apply_irq_affinity(expected_irq_affinity)
        state['after'] = verify_active(plan, before, contents, profile,
                                       expected_irq_affinity, runtime)
        state['status'] = 'active'
        write_json(record / 'state.json', state)
        cancel_timer(attempt)
        return state
    except Exception as activation_error:
        state['activation_error'] = str(activation_error)
        write_json(record / 'state.json', state)
        try:
            restore_locked(attempt)
        except Exception as recovery_error:
            print(f'automatic restoration failed; retained timer and record: {recovery_error}',
                  file=sys.stderr)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'apply', 'restore'))
    parser.add_argument('--attempt', required=True)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--manifest-sha')
    parser.add_argument('--runtime-bundle', type=Path)
    parser.add_argument('--runtime-manifest-sha')
    parser.add_argument('--boot-id')
    parser.add_argument('--profile', choices=tuple(sorted(SUPPORTED_IRQ_PROFILES)))
    args = parser.parse_args()
    ensure(ATTEMPT.fullmatch(args.attempt), 'attempt ID invalid')
    ensure(os.geteuid() == 0 and sys.platform == 'linux', 'Ubuntu root required')
    ensure(Path('/etc/os-release').read_text().find('VERSION_ID="24.04"') >= 0,
           'Ubuntu 24.04 required')
    if args.action == 'inspect':
        ensure(args.bundle and args.manifest_sha and args.boot_id and args.profile is None,
               'inspect requires bundle, manifest SHA and boot ID')
        plan, _ = verify_bundle(args.bundle, args.manifest_sha)
        if plan.get('runtime_artifacts') is not None:
            ensure(args.runtime_bundle and args.runtime_manifest_sha,
                   'campaign inspect requires its runtime bundle')
            runtime = runtime_expectation(args.runtime_bundle,
                                          args.runtime_manifest_sha, plan)
        else:
            ensure(args.runtime_bundle is None and
                   args.runtime_manifest_sha is None,
                   'ordinary inspect cannot accept a runtime bundle')
            runtime = None
        result = {'status': 'inspect-pass', 'activation_authorized': False,
                  'runtime': runtime, 'before': capture_before(plan, args.boot_id)}
    else:
        ROOT.mkdir(mode=0o700, exist_ok=True)
        with open(ROOT / '.lock', 'a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if args.action == 'restore':
                ensure(args.bundle is None and args.manifest_sha is None and
                       args.runtime_bundle is None and
                       args.runtime_manifest_sha is None and
                       args.boot_id is None and args.profile is None,
                       'restore accepts only an attempt ID')
                result = restore_locked(args.attempt)
            else:
                ensure(args.bundle and args.manifest_sha and args.boot_id,
                       'apply requires bundle, manifest SHA and boot ID')
                result = apply_locked(args.attempt, args.bundle,
                                      args.manifest_sha, args.boot_id,
                                      args.profile or 'irqbalance-off-unpinned',
                                      args.runtime_bundle,
                                      args.runtime_manifest_sha)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'phase5-package-vm: {error}', file=sys.stderr)
        sys.exit(1)
