from __future__ import annotations

from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
import subprocess

from zapret_hub.services.linux_zapret2 import LinuxZapret2Service, managed_ports, normalize_ports

PROJECT_ROOT = Path(__file__).resolve().parents[1]
HELPER = PROJECT_ROOT / "packaging" / "linux" / "zapret-hub-zapret2-config"
POLKIT = PROJECT_ROOT / "packaging" / "polkit" / "49-zapret-hub.rules"

STOCK_CONFIG = (
    "# Linux desktop profile managed by Zapret Hub.\n"
    '. "${ZAPRET_BASE:-/opt/zapret2}/config.default"\n'
    "\n"
    "NFQWS2_ENABLE=1\n"
    "MODE_FILTER=hostlist\n"
)
DISCORD_UDP = "443,19294-19344,50000-50100"


def _load_helper():
    loader = SourceFileLoader("zapret_hub_zapret2_config", str(HELPER))
    spec = spec_from_loader(loader.name, loader)
    module = module_from_spec(spec)
    loader.exec_module(module)
    return module


helper = _load_helper()


def test_helper_writes_ports_and_udp_profile(tmp_path: Path) -> None:
    config = tmp_path / "config"
    config.write_text(STOCK_CONFIG)

    assert helper.apply(str(config), "80,443", DISCORD_UDP) is True

    text = config.read_text()
    assert text.startswith(STOCK_CONFIG)
    assert "NFQWS2_PORTS_TCP=80,443\n" in text
    assert f"NFQWS2_PORTS_UDP={DISCORD_UDP}\n" in text
    assert 'NFQWS2_OPT="$NFQWS2_OPT\n' in text
    assert "--new --filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun" in text
    # 443 is already handled by the stock QUIC profile: no duplicate profile.
    assert "--filter-udp=443," not in text
    assert "--filter-tcp=" not in text
    assert managed_ports(text) == ("80,443", DISCORD_UDP)


def test_helper_is_idempotent_and_replaces_previous_block(tmp_path: Path) -> None:
    config = tmp_path / "config"
    config.write_text(STOCK_CONFIG)
    helper.apply(str(config), "80,443,8443", "443")

    assert helper.apply(str(config), "80,443,8443", "443") is False
    assert helper.apply(str(config), "80,443", "443,3478") is True

    text = config.read_text()
    assert text.count(helper.BEGIN) == 1
    assert text.count(helper.END) == 1
    assert "8443" not in text
    assert "--filter-udp=3478" in text


def test_helper_removes_block_when_defaults_requested(tmp_path: Path) -> None:
    config = tmp_path / "config"
    config.write_text(STOCK_CONFIG)
    helper.apply(str(config), "80,443", DISCORD_UDP)

    assert helper.apply(str(config), "80,443", "443") is True

    assert config.read_text() == STOCK_CONFIG
    assert helper.apply(str(config), "80,443", "443") is False


def test_helper_adds_tls_profile_for_extra_tcp_ports(tmp_path: Path) -> None:
    config = tmp_path / "config"
    config.write_text(STOCK_CONFIG)

    helper.apply(str(config), "80,443,2053,8443", "443")

    text = config.read_text()
    assert "--new --filter-tcp=2053,8443 --filter-l7=tls <HOSTLIST>" in text


def test_helper_rejects_malformed_input(tmp_path: Path) -> None:
    config = tmp_path / "config"
    config.write_text(STOCK_CONFIG)
    for bad in ("", "80;rm", "80,$(id)", "0", "70000", "1-2-3", "a", "443\n443", "1," * 200):
        try:
            helper.apply(str(config), bad, "443")
        except ValueError:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"accepted {bad!r}")
    assert config.read_text() == STOCK_CONFIG


def test_helper_refuses_damaged_markers(tmp_path: Path) -> None:
    config = tmp_path / "config"
    damaged = STOCK_CONFIG + helper.BEGIN + "\nNFQWS2_PORTS_UDP=1\n"
    config.write_text(damaged)
    try:
        helper.apply(str(config), "80,443", DISCORD_UDP)
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("damaged block was accepted")
    assert config.read_text() == damaged


def test_generated_config_is_valid_shell_and_keeps_stock_profiles(tmp_path: Path) -> None:
    base = tmp_path / "config.default"
    base.write_text('NFQWS2_OPT="\n--filter-udp=443 --filter-l7=quic <HOSTLIST_NOAUTO> --payload=quic_initial\n"\n')
    config = tmp_path / "config"
    config.write_text('. "' + str(base) + '"\n')
    helper.apply(str(config), "80,443", DISCORD_UDP)

    result = subprocess.run(
        ["/bin/sh", "-c", f'. "{config}"; printf "%s" "$NFQWS2_OPT"; echo; echo "$NFQWS2_PORTS_UDP"'],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "--filter-udp=443 --filter-l7=quic" in result.stdout
    assert "--new --filter-udp=19294-19344,50000-50100" in result.stdout
    assert result.stdout.strip().endswith(DISCORD_UDP)


def test_normalize_ports_drops_junk() -> None:
    assert normalize_ports("443; 19294-19344,,x,50100-50000,443", "443") == "443,19294-19344,50000-50100"
    assert normalize_ports("garbage", "80,443") == "80,443"


class FakeRunner:
    def __init__(self, returncode: int = 0, stderr: str = "") -> None:
        self.commands: list[list[str]] = []
        self.returncode = returncode
        self.stderr = stderr

    def __call__(self, command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        return subprocess.CompletedProcess(command, self.returncode, "changed\n", self.stderr)


def _service(tmp_path: Path, runner: FakeRunner, *, helper_exists: bool = True, root: bool = False) -> LinuxZapret2Service:
    zapret_root = tmp_path / "zapret2"
    zapret_root.mkdir(exist_ok=True)
    (zapret_root / "config").write_text(STOCK_CONFIG)
    fake_helper = tmp_path / "zapret-hub-zapret2-config"
    if helper_exists:
        fake_helper.write_text("#!/bin/sh\n")
    return LinuxZapret2Service(
        root_candidates=[zapret_root],
        runner=runner,
        which=lambda name: f"/usr/bin/{name}",
        geteuid=lambda: 0 if root else 1000,
        platform_name="linux",
        config_helper=fake_helper,
    )


def test_sync_ports_calls_helper_through_pkexec(tmp_path: Path) -> None:
    runner = FakeRunner()
    service = _service(tmp_path, runner)

    result = service.sync_ports("80, 443", "443,19294-19344,50000-50100")

    assert result.status == "applied"
    assert runner.commands == [
        ["/usr/bin/pkexec", str(tmp_path / "zapret-hub-zapret2-config"), "80,443", DISCORD_UDP]
    ]


def test_sync_ports_skips_when_defaults_and_untouched(tmp_path: Path) -> None:
    runner = FakeRunner()
    service = _service(tmp_path, runner)

    assert service.sync_ports("80,443", "443").status == "unchanged"
    assert runner.commands == []


def test_sync_ports_skips_when_block_already_matches(tmp_path: Path) -> None:
    runner = FakeRunner()
    service = _service(tmp_path, runner)
    config = tmp_path / "zapret2" / "config"
    helper.apply(str(config), "80,443", DISCORD_UDP)

    assert service.sync_ports("80,443", DISCORD_UDP).status == "unchanged"
    assert runner.commands == []
    # ...but resetting to defaults must remove the block.
    assert service.sync_ports("80,443", "443").status == "applied"


def test_sync_ports_reports_missing_helper_and_helper_failure(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    missing = _service(tmp_path / "a", FakeRunner(), helper_exists=False)
    result = missing.sync_ports("80,443", DISCORD_UDP)
    assert result.status == "error"
    assert "install.sh" in result.message

    (tmp_path / "b").mkdir()
    failing = _service(tmp_path / "b", FakeRunner(returncode=126, stderr="Error executing command as another user"))
    result = failing.sync_ports("80,443", DISCORD_UDP)
    assert result.status == "error"
    assert "Error executing command" in result.message


def test_sync_ports_dry_run_and_root(tmp_path: Path) -> None:
    runner = FakeRunner()
    service = _service(tmp_path, runner, root=True)

    result = service.sync_ports("80,443", DISCORD_UDP, dry_run=True)

    assert result.status == "planned"
    assert result.command[0] == str(tmp_path / "zapret-hub-zapret2-config")
    assert runner.commands == []


def test_restart_expects_running_service(tmp_path: Path) -> None:
    class Runner:
        def __init__(self) -> None:
            self.commands: list[list[str]] = []

        def __call__(self, command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            self.commands.append(command)
            return subprocess.CompletedProcess(command, 0, "active\n" if "is-active" in command else "", "")

    runner = Runner()
    service = _service(tmp_path, runner)  # type: ignore[arg-type]

    result = service.restart()

    assert result.status == "running"
    assert runner.commands[0] == ["/usr/bin/pkexec", "/usr/bin/systemctl", "restart", "zapret2.service"]


def test_polkit_allows_only_numeric_port_helper_arguments() -> None:
    rules = POLKIT.read_text()
    assert "/usr/local/libexec/zapret-hub-zapret2-config" in rules
    assert "[0-9,-]{1,256} [0-9,-]{1,256}$" in rules
    assert (PROJECT_ROOT / "scripts" / "install_linux_system.sh").read_text().count("zapret-hub-zapret2-config") >= 1
    assert HELPER.stat().st_mode & 0o111


def _manager(service_calls: list[str], *, sync_status: str, running: bool):
    from types import SimpleNamespace

    from zapret_hub.services.components import ProcessManager

    manager = ProcessManager.__new__(ProcessManager)
    manager._states = {}
    manager.settings = SimpleNamespace(
        get=lambda: SimpleNamespace(zapret2_tcp_ports="80,443", zapret2_udp_ports=DISCORD_UDP)
    )
    manager.logging = SimpleNamespace(log=lambda *args, **kwargs: service_calls.append("log:" + str(args[1])))

    def result(status: str, message: str = ""):
        return SimpleNamespace(status=status, message=message, command=())

    manager._linux_zapret2 = SimpleNamespace(
        sync_ports=lambda tcp, udp: service_calls.append(f"sync:{tcp}|{udp}") or result(sync_status, "boom"),
        status=lambda: result("running" if running else "stopped"),
        start=lambda: service_calls.append("start") or result("running"),
        restart=lambda: service_calls.append("restart") or result("running"),
    )
    return manager


def test_start_pushes_ports_to_config_before_starting_service() -> None:
    calls: list[str] = []
    manager = _manager(calls, sync_status="applied", running=False)

    state = manager._start_linux_zapret2("zapret2")

    assert state.status == "running"
    assert calls[0] == f"sync:80,443|{DISCORD_UDP}"
    assert "start" in calls and "restart" not in calls


def test_start_restarts_when_config_changed_under_running_service() -> None:
    calls: list[str] = []
    manager = _manager(calls, sync_status="applied", running=True)

    manager._start_linux_zapret2("zapret2")

    assert "restart" in calls and "start" not in calls


def test_start_still_starts_service_when_port_sync_fails() -> None:
    calls: list[str] = []
    manager = _manager(calls, sync_status="error", running=False)

    state = manager._start_linux_zapret2("zapret2")

    assert state.status == "running"
    assert "log:Could not apply Zapret2 ports to /opt/zapret2/config" in calls
    assert "start" in calls
