"""Low-level device checks. Commands are built as argument arrays; secrets are never logged."""
from __future__ import annotations
import subprocess
from dataclasses import dataclass


@dataclass
class PollResult:
    ok: bool
    value: str = ""
    error: str = ""


def _run(command: list[str], timeout: int = 12) -> PollResult:
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return PollResult(False, error="Тайм-аут опроса устройства")
    if result.returncode != 0:
        return PollResult(False, error=(result.stderr or result.stdout or "Ошибка команды опроса").strip())
    return PollResult(True, value=result.stdout.strip())


def _snmp_command(command_name: str, credentials: dict) -> list[str]:
    """Build an SNMP command without ever exposing credentials in logs."""
    version = credentials.get("version", "2c")
    command = [command_name, "-On", "-t", str(credentials.get("timeout", 5)), "-r", str(credentials.get("retries", 1))]
    if version == "3":
        security_level = credentials.get("security_level", "authPriv")
        command += ["-v3", "-l", security_level, "-u", credentials["username"]]
        if security_level in ("authNoPriv", "authPriv"):
            command += ["-a", credentials.get("auth_protocol", "SHA"), "-A", credentials["auth_password"]]
        if security_level == "authPriv":
            command += ["-x", credentials.get("privacy_protocol", "AES"), "-X", credentials["privacy_password"]]
    else:
        command += ["-v2c", "-c", credentials["community"]]
    return command


def poll_snmp(address: str, credentials: dict, oid: str) -> PollResult:
    result = _run(_snmp_command("snmpget", credentials) + [address, oid])
    # net-snmp may exit successfully even when the agent explicitly says that
    # an OID does not exist. Treat that as an item error, not a metric value.
    if result.ok and any(marker in result.value for marker in ("No Such Object", "No Such Instance", "endOfMibView")):
        return PollResult(False, error=result.value)
    return result


def walk_snmp(address: str, credentials: dict, oid: str) -> PollResult:
    """Read a SNMP subtree for a template discovery rule."""
    return _run(_snmp_command("snmpwalk", credentials) + [address, oid], timeout=25)


def poll_ipmi(address: str, credentials: dict, sensor: str | None = None) -> PollResult:
    command = ["ipmitool", "-I", credentials.get("interface", "lanplus"), "-H", address, "-U", credentials["username"], "-P", credentials["password"], "sensor"]
    if sensor:
        command.append("get")
        command.append(sensor)
    return _run(command, timeout=20)


def test_connection(protocol: str, address: str, credentials: dict) -> PollResult:
    if protocol.startswith("snmp"):
        return poll_snmp(address, credentials, "1.3.6.1.2.1.1.1.0")
    if protocol == "ipmi":
        return poll_ipmi(address, credentials)
    return PollResult(False, error="Неизвестный протокол")

