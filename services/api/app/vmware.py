"""Safe VMware inventory access used by ESXi and vCenter connections."""
from __future__ import annotations

import ssl
import http.client
import threading
from contextlib import contextmanager
from dataclasses import dataclass
import httpx


_connection_patch_lock = threading.Lock()


class _NoSNIHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection for older ESXi that rejects the SNI extension.

    It is deliberately used only with an unverified context selected by the
    administrator.  Verified TLS must retain SNI for hostname validation.
    """
    def __init__(self, host, port=None, *legacy_args, **kwargs):
        """Accept both modern http.client and legacy pyVmomi constructors.

        Older pyVmomi calls ``HTTPSConnection(host, port, key_file,
        cert_file, context=...)``.  Python 3.12 removed those positional
        certificate arguments, so consume them while retaining the supplied
        SSL context.
        """
        context = kwargs.pop("context", None)
        timeout = kwargs.pop("timeout", None)
        source_address = kwargs.pop("source_address", None)
        kwargs.pop("check_hostname", None)
        blocksize = kwargs.pop("blocksize", 8192)
        super().__init__(
            host,
            port=port,
            timeout=timeout,
            source_address=source_address,
            context=context,
            blocksize=blocksize,
        )

    def connect(self):  # pragma: no cover - requires a legacy ESXi endpoint
        http.client.HTTPConnection.connect(self)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=None)


@contextmanager
def _without_sni():
    """Temporarily let pyVmomi construct no-SNI HTTPS connections.

    pyVmomi imports the connection class into two modules.  The adapter keeps
    the selected class on the created stub, so restoring the module globals
    after SmartConnect is safe for the active VMware session.
    """
    from pyVim import connect as vim_connect  # type: ignore
    from pyVmomi import SoapAdapter, five  # type: ignore
    with _connection_patch_lock:
        # pyVmomi 8 and 9 expose this class differently: directly in the
        # module or through its ``http_client`` compatibility module.
        targets: list[tuple[object, str, object]] = []
        for owner in (
            vim_connect,
            getattr(vim_connect, "http_client", None),
            SoapAdapter,
            getattr(SoapAdapter, "http_client", None),
            five,
            http.client,
        ):
            if owner is not None and hasattr(owner, "HTTPSConnection"):
                targets.append((owner, "HTTPSConnection", getattr(owner, "HTTPSConnection")))
                setattr(owner, "HTTPSConnection", _NoSNIHTTPSConnection)
        if not targets:
            raise RuntimeError("Установленная версия pyVmomi не поддерживает режим ESXi по IP без SNI")
        try:
            yield
        finally:
            for owner, name, original in reversed(targets):
                setattr(owner, name, original)


@dataclass
class VMwareResult:
    ok: bool
    product: str = ""
    virtual_machines: list[dict] | None = None
    error: str = ""


def _base_url(address: str, port: int) -> str:
    host = f"[{address}]" if ":" in address and not address.startswith("[") else address
    return f"https://{host}:{port}"


def _rest_inventory(address: str, credentials: dict) -> VMwareResult:
    """Use the vSphere REST API first, which handles ESXi-by-IP cleanly."""
    verify_tls = credentials.get("verify_tls", True)
    try:
        port = int(credentials.get("port", 443))
    except (TypeError, ValueError):
        port = 443
    base_url = _base_url(address, port)
    auth = (str(credentials.get("username") or ""), str(credentials.get("password") or ""))
    errors: list[str] = []
    # Current API (vSphere 7+) then compatible legacy REST API (6.5+).
    variants = (
        ("/api/session", "/api/vcenter/vm", "modern"),
        ("/rest/com/vmware/cis/session", "/rest/vcenter/vm", "legacy"),
    )
    try:
        with httpx.Client(verify=verify_tls, timeout=20) as client:
            for session_path, inventory_path, kind in variants:
                try:
                    session = client.post(base_url + session_path, auth=auth)
                    if session.is_error:
                        detail = session.text.strip().replace("\n", " ")[:300]
                        raise RuntimeError(f"HTTP {session.status_code}" + (f": {detail}" if detail else ""))
                    token_body = session.json()
                    token = token_body.get("value") if isinstance(token_body, dict) else token_body
                    if not token:
                        raise RuntimeError("Сервер VMware не вернул токен сессии")
                    response = client.get(
                        base_url + inventory_path,
                        headers={"vmware-api-session-id": str(token)},
                    )
                    if response.is_error:
                        detail = response.text.strip().replace("\n", " ")[:300]
                        raise RuntimeError(f"HTTP {response.status_code}" + (f": {detail}" if detail else ""))
                    body = response.json()
                    values = body.get("value", []) if isinstance(body, dict) else body
                    if not isinstance(values, list):
                        raise RuntimeError("Некорректный ответ VMware REST API")
                    virtual_machines = []
                    for vm in values:
                        if not isinstance(vm, dict):
                            continue
                        moid = str(vm.get("vm") or vm.get("id") or "")
                        if not moid:
                            continue
                        power_state = str(vm.get("power_state") or vm.get("powerState") or "unknown")
                        virtual_machines.append({
                            "moid": moid,
                            "name": str(vm.get("name") or moid),
                            "address": str(vm.get("guest_ip") or vm.get("ip_address") or f"vmware://{moid}"),
                            "power_state": power_state.removeprefix("POWERED_").removeprefix("powered"),
                            "guest_os": str(vm.get("guest_OS") or vm.get("guest_os") or ""),
                        })
                    return VMwareResult(True, product=f"VMware REST API ({kind})", virtual_machines=virtual_machines)
                except Exception as exc:
                    errors.append(_error(exc))
    except Exception as exc:
        errors.append(_error(exc))
    return VMwareResult(False, error="; ".join(dict.fromkeys(errors))[:700])


def _connect(address: str, credentials: dict):
    try:
        from pyVim.connect import SmartConnect  # type: ignore
    except ImportError as exc:  # Helpful during a partial/old deployment.
        raise RuntimeError("Компонент VMware не установлен. Пересоберите контейнер коллектора.") from exc
    verify_tls = credentials.get("verify_tls", True)
    context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    try:
        port = int(credentials.get("port", 443))
    except (TypeError, ValueError):
        port = 443
    options = {
        "host": address,
        "user": str(credentials.get("username") or ""),
        "pwd": str(credentials.get("password") or ""),
        "port": port,
        "sslContext": context,
    }
    # Some old ESXi builds reject any SNI extension when their self-signed
    # certificate is used via an IP address.  Allow that explicit pilot mode.
    if not verify_tls:
        with _without_sni():
            return SmartConnect(**options)
    return SmartConnect(**options)


def _error(exc: Exception) -> str:
    # VMware errors sometimes include the endpoint but must never disclose a
    # password.  Limit the message shown in the operator UI.
    text = str(exc).replace("\n", " ").strip()
    return (text or "Не удалось подключиться к VMware API")[:500]


def test_vmware(address: str, credentials: dict) -> VMwareResult:
    rest_result = _rest_inventory(address, credentials)
    if rest_result.ok:
        return VMwareResult(True, product=rest_result.product)
    service_instance = None
    try:
        from pyVim.connect import Disconnect  # type: ignore
        service_instance = _connect(address, credentials)
        about = service_instance.RetrieveContent().about
        return VMwareResult(True, product=f"{about.fullName} ({about.version})")
    except Exception as exc:
        detail = _error(exc)
        return VMwareResult(False, error=f"{rest_result.error}; SOAP: {detail}".strip("; "))
    finally:
        if service_instance is not None:
            try:
                Disconnect(service_instance)
            except Exception:
                pass


def discover_virtual_machines(address: str, credentials: dict) -> VMwareResult:
    """Read the VM inventory without changing anything on the hypervisor."""
    rest_result = _rest_inventory(address, credentials)
    if rest_result.ok:
        return rest_result
    service_instance = None
    try:
        from pyVim.connect import Disconnect  # type: ignore
        from pyVmomi import vim  # type: ignore
        service_instance = _connect(address, credentials)
        content = service_instance.RetrieveContent()
        view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
        virtual_machines: list[dict] = []
        try:
            for vm in view.view:
                # Templates are not running virtual machines and should not
                # become monitoring hosts.
                if getattr(getattr(vm, "config", None), "template", False):
                    continue
                summary = vm.summary
                config = getattr(summary, "config", None)
                runtime = getattr(summary, "runtime", None)
                guest = getattr(summary, "guest", None)
                name = str(getattr(config, "name", "") or getattr(vm, "name", "VM"))
                moid = str(getattr(vm, "_moId", "") or getattr(config, "instanceUuid", "") or getattr(config, "uuid", ""))
                if not moid:
                    continue
                ip_address = str(getattr(guest, "ipAddress", "") or "")
                power_state = str(getattr(runtime, "powerState", "unknown"))
                virtual_machines.append({
                    "moid": moid,
                    "name": name,
                    "address": ip_address or f"vmware://{moid}",
                    "power_state": power_state.removeprefix("powered"),
                    "guest_os": str(getattr(config, "guestFullName", "") or ""),
                })
        finally:
            view.Destroy()
        about = content.about
        return VMwareResult(True, product=f"{about.fullName} ({about.version})", virtual_machines=virtual_machines)
    except Exception as exc:
        detail = _error(exc)
        return VMwareResult(False, error=f"{rest_result.error}; SOAP: {detail}".strip("; "))
    finally:
        if service_instance is not None:
            try:
                Disconnect(service_instance)
            except Exception:
                pass
