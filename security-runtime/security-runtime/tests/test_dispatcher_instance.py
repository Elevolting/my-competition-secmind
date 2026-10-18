from pathlib import Path
import subprocess
import sys

from security_runtime.dispatcher.runtime.instance_lock import DispatcherInstance


def test_dispatcher_lock_blocks_other_process_and_releases(tmp_path: Path):
    config = tmp_path / 'dispatch.yaml'
    config.write_text('server: http://localhost')
    script = (
        'from pathlib import Path; '
        'from security_runtime.dispatcher.runtime.instance_lock import DispatcherInstance; '
        f'lock=DispatcherInstance(Path({str(config)!r})); lock.__enter__()'
    )
    with DispatcherInstance(config):
        blocked = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, timeout=10)
        assert blocked.returncode != 0
        assert 'already running' in blocked.stderr
    allowed = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, timeout=10)
    assert allowed.returncode == 0, allowed.stderr
    # A stale lock file must not block a later owner.
    with DispatcherInstance(config):
        pass
