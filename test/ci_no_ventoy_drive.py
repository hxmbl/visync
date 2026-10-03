"""Force drive detection to report nothing, so CI matches a fresh runner.

Why this exists
---------------
``test_cli_exits_130_on_interrupt`` passed on a maintainer's machine and failed
on CI. Not because of Python version or a real defect: the test invoked
``visync sync`` without ``--drive``, so it relied on ``find_ventoy_drives()``
finding the USB stick. With the stick plugged in the command reached the
download and hit the patched KeyboardInterrupt; with no stick it exited 1 at
"no Ventoy drives detected" and never got there.

That is the worst shape of green — a test whose result depends on what is
plugged into the machine running it. CI is the environment with nothing
plugged in, so CI is the honest place to find it, and this makes that
guarantee permanent rather than incidental.

Enabled by CI with ``pytest -p ci_no_ventoy_drive``. It is *not* enabled for
local runs, so the hardware tests in ``test_finder.py`` still run against a real
drive locally; under this plugin ``HAS_VENTOY`` is False and they skip, exactly
as they already do on CI.

Tests that want a drive supply one — patch ``find_ventoy_drives`` themselves,
or pass ``--drive`` pointing at a temp directory. Tests that want none get it
for free.
"""

from unittest.mock import patch

# The visync imports and the module table are built inside pytest_configure, not
# at module scope. pytest loads plugins before pytest-cov starts measuring, so
# importing visync here would mean every module-level line in download.py,
# finder.py, main.py, net.py, output.py and verify.py ran before coverage began
# and was reported as untested — which cost 11 points of coverage and failed the
# --cov-fail-under=70 gate on every Python version. Deferring the import keeps
# the first import inside the measured run, where the test suite does it anyway.


def _detection_entry_points():
    """Every namespace that holds its own reference to find_ventoy_drives.

    main.py and download.py bind it in with `from visync.finder import ...`, so
    patching only visync.finder would leave two live copies behind and the stub
    would not simulate an empty machine at all.
    """
    import visync.download
    import visync.finder
    import visync.main

    return (
        (visync.finder, "find_ventoy_drives"),
        (visync.main, "find_ventoy_drives"),
        (visync.download, "find_ventoy_drives"),
    )


def pytest_configure(config):
    for module, name in _detection_entry_points():
        if not hasattr(module, name):
            continue
        started = patch.object(module, name, return_value=[])
        started.start()
        config.add_cleanup(started.stop)


def pytest_report_header(config):
    return "visync: drive detection stubbed to [] — emulating a runner with no Ventoy drive"
