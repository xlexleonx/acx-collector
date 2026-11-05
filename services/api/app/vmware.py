"""Safe VMware inventory access used by ESXi and vCenter connections."""
from __future__ import annotations

import ssl
from dataclasses import dataclass


@dataclass
class VMwareResult:
    ok: bool
    product: str = ""
    virtual_machines: list[dict] | None = None
    error: str = ""


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
    return SmartConnect(
        host=address,
        user=str(credentials.get("username") or ""),
        pwd=str(credentials.get("password") or ""),
        port=port,
        sslContext=context,
    )


def _error(exc: Exception) -> str:
    # VMware errors sometimes include the endpoint but must never disclose a
    # password.  Limit the message shown in the operator UI.
    text = str(exc).replace("\n", " ").strip()
    return (text or "Не удалось подключиться к VMware API")[:500]


def test_vmware(address: str, credentials: dict) -> VMwareResult:
    service_instance = None
    try:
        from pyVim.connect import Disconnect  # type: ignore
        service_instance = _connect(address, credentials)
        about = service_instance.RetrieveContent().about
        return VMwareResult(True, product=f"{about.fullName} ({about.version})")
    except Exception as exc:
        return VMwareResult(False, error=_error(exc))
    finally:
        if service_instance is not None:
            try:
                Disconnect(service_instance)
            except Exception:
                pass


def discover_virtual_machines(address: str, credentials: dict) -> VMwareResult:
    """Read the VM inventory without changing anything on the hypervisor."""
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
        return VMwareResult(False, error=_error(exc))
    finally:
        if service_instance is not None:
            try:
                Disconnect(service_instance)
            except Exception:
                pass
