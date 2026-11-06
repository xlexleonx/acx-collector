"""VMware inventory over the vSphere SOAP API (the same API family as Zabbix)."""
from __future__ import annotations

import http.client
import ssl
from dataclasses import dataclass
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape


VIM_NS = "urn:vim25"
SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"


@dataclass
class VMwareResult:
    ok: bool
    product: str = ""
    virtual_machines: list[dict] | None = None
    host_systems: list[dict] | None = None
    error: str = ""


class _NoSNIHTTPSConnection(http.client.HTTPSConnection):
    """Direct HTTPS client for old ESXi with broken SNI handling by IP."""
    def connect(self):
        http.client.HTTPConnection.connect(self)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=None)


def _local(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _text(element: ET.Element, name: str, default: str = "") -> str:
    for child in element.iter():
        if _local(child) == name and child.text:
            return child.text.strip()
    return default


def _child_text(element: ET.Element, name: str, default: str = "") -> str:
    for child in element:
        if _local(child) == name and child.text:
            return child.text.strip()
    return default


def _child(element: ET.Element, name: str) -> ET.Element | None:
    """Find a direct child without relying on the VMware XML namespace."""
    for value in element:
        if _local(value) == name:
            return value
    return None


def _soap_envelope(body: str) -> bytes:
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<soapenv:Envelope xmlns:soapenv="{SOAP_NS}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f"<soapenv:Body>{body}</soapenv:Body></soapenv:Envelope>"
    ).encode("utf-8")


class _VimSoapClient:
    def __init__(self, address: str, credentials: dict):
        self.address = address.strip("[]")
        try:
            self.port = int(credentials.get("port", 443))
        except (TypeError, ValueError):
            self.port = 443
        self.verify_tls = bool(credentials.get("verify_tls", True))
        self.context = ssl.create_default_context() if self.verify_tls else ssl._create_unverified_context()
        self.cookie = ""

    def _connection(self):
        connection_type = http.client.HTTPSConnection if self.verify_tls else _NoSNIHTTPSConnection
        return connection_type(self.address, self.port, timeout=20, context=self.context)

    def call(self, body: str) -> ET.Element:
        connection = self._connection()
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": '"urn:vim25/5.5"',
            "User-Agent": "ACROTIX-Collector/0.1",
        }
        if self.cookie:
            headers["Cookie"] = self.cookie
        try:
            connection.request("POST", "/sdk", body=_soap_envelope(body), headers=headers)
            response = connection.getresponse()
            raw = response.read()
            cookie = response.getheader("Set-Cookie")
            if cookie:
                self.cookie = cookie.split(";", 1)[0]
        finally:
            connection.close()
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            text = raw.decode("utf-8", errors="replace").replace("\n", " ")[:300]
            raise RuntimeError(f"VMware вернул некорректный XML (HTTP {response.status}): {text}") from exc
        if response.status not in (200, 500):
            detail = _text(root, "faultstring") or raw.decode("utf-8", errors="replace").replace("\n", " ")[:300]
            raise RuntimeError(f"VMware SOAP HTTP {response.status}: {detail}")
        fault = _text(root, "faultstring")
        if fault:
            raise RuntimeError(f"VMware SOAP: {fault}")
        return root


def _service_content(client: _VimSoapClient) -> dict[str, str]:
    root = client.call(
        f'<RetrieveServiceContent xmlns="{VIM_NS}"><_this type="ServiceInstance">ServiceInstance</_this></RetrieveServiceContent>'
    )
    fields = ("rootFolder", "viewManager", "propertyCollector", "sessionManager", "perfManager")
    values = {field: _text(root, field) for field in fields}
    if not all(values[field] for field in ("rootFolder", "viewManager", "propertyCollector", "sessionManager")):
        raise RuntimeError("VMware SOAP не вернул служебные объекты API")
    values["apiVersion"] = _text(root, "apiVersion", "vSphere SOAP")
    return values


def _login(client: _VimSoapClient, session_manager: str, credentials: dict) -> None:
    client.call(
        f'<Login xmlns="{VIM_NS}"><_this type="SessionManager">{escape(session_manager)}</_this>'
        f"<userName>{escape(str(credentials.get('username') or ''))}</userName>"
        f"<password>{escape(str(credentials.get('password') or ''))}</password></Login>"
    )


def _container_view(client: _VimSoapClient, view_manager: str, root_folder: str, entity_type: str) -> str:
    root = client.call(
        f'<CreateContainerView xmlns="{VIM_NS}"><_this type="ViewManager">{escape(view_manager)}</_this>'
        f'<container type="Folder">{escape(root_folder)}</container><type>{escape(entity_type)}</type><recursive>true</recursive>'
        "</CreateContainerView>"
    )
    view = _text(root, "returnval")
    if not view:
        raise RuntimeError("VMware SOAP не создал представление виртуальных машин")
    return view


def _property_page(
    client: _VimSoapClient,
    property_collector: str,
    container_view: str,
    entity_type: str,
    paths: tuple[str, ...],
    token: str = "",
) -> ET.Element:
    if token:
        return client.call(
            f'<ContinueRetrievePropertiesEx xmlns="{VIM_NS}"><_this type="PropertyCollector">{escape(property_collector)}</_this>'
            f"<token>{escape(token)}</token></ContinueRetrievePropertiesEx>"
        )
    path_xml = "".join(f"<pathSet>{path}</pathSet>" for path in paths)
    return client.call(
        f'<RetrievePropertiesEx xmlns="{VIM_NS}"><_this type="PropertyCollector">{escape(property_collector)}</_this><specSet>'
        f"<propSet><type>{escape(entity_type)}</type>{path_xml}</propSet><objectSet>"
        f'<obj type="ContainerView">{escape(container_view)}</obj><skip>false</skip>'
        '<selectSet xsi:type="TraversalSpec"><name>viewTraversal</name><type>ContainerView</type><path>view</path><skip>false</skip></selectSet>'
        "</objectSet></specSet><options><maxObjects>1000</maxObjects></options></RetrievePropertiesEx>"
    )


VM_PROPERTIES = (
    "name", "runtime.powerState", "runtime.connectionState", "runtime.bootTime", "runtime.maxCpuUsage", "runtime.maxMemoryUsage",
    "runtime.host", "runtime.consolidationNeeded", "guest.ipAddress", "guest.hostName", "guest.guestFullName", "guest.guestId",
    "guest.guestFamily", "guest.guestState", "guest.toolsStatus", "guest.toolsRunningStatus", "config.guestFullName", "config.template",
    "config.uuid", "config.instanceUuid", "config.version", "config.changeVersion", "config.annotation", "config.files.vmPathName", "config.hardware.numCPU",
    "config.hardware.numCoresPerSocket", "config.hardware.memoryMB", "config.cpuHotAddEnabled", "config.memoryHotAddEnabled",
    "summary.quickStats.overallCpuUsage", "summary.quickStats.overallCpuDemand", "summary.quickStats.staticCpuEntitlement",
    "summary.quickStats.staticMemoryEntitlement", "summary.quickStats.guestMemoryUsage",
    "summary.quickStats.hostMemoryUsage", "summary.quickStats.balloonedMemory", "summary.quickStats.swappedMemory",
    "summary.quickStats.compressedMemory", "summary.quickStats.privateMemory", "summary.quickStats.sharedMemory",
    "summary.quickStats.consumedOverheadMemoryResource", "summary.quickStats.uptimeSeconds", "summary.storage.committed",
    "summary.storage.uncommitted", "summary.storage.unshared", "guest.toolsVersion", "guest.toolsVersionStatus2",
    "guest.disk", "config.hardware.device", "rootSnapshotList",
)

HOST_PROPERTIES = (
    "name", "runtime.connectionState", "runtime.inMaintenanceMode", "runtime.powerState", "summary.hardware.vendor",
    "summary.hardware.model", "summary.hardware.cpuModel", "summary.hardware.numCpuCores", "summary.hardware.numCpuThreads",
    "summary.hardware.cpuMhz", "summary.hardware.memorySize", "summary.quickStats.overallCpuUsage",
    "summary.quickStats.overallMemoryUsage", "summary.quickStats.uptime", "config.product.fullName", "config.product.version",
    "config.product.build",
)


def _type_name(element: ET.Element) -> str:
    """Read xsi:type regardless of the namespace prefix used by ESXi."""
    for attribute, value in element.attrib.items():
        if attribute.rsplit("}", 1)[-1] == "type":
            return value.rsplit(":", 1)[-1]
    return ""


def _hardware_devices(value: ET.Element | None) -> tuple[list[dict], list[dict]]:
    """Return real virtual-disk and NIC identifiers for per-device counters."""
    if value is None:
        return [], []
    controllers: dict[str, str] = {}
    disks: list[dict] = []
    interfaces: list[dict] = []
    for element in value.iter():
        kind = _type_name(element)
        key = _child_text(element, "key")
        if "SCSIController" in kind and key:
            controllers[key] = _child_text(element, "busNumber")
        elif kind == "VirtualDisk" and key:
            info = _child(element, "deviceInfo")
            disks.append({
                "key": key,
                "label": _child_text(info if info is not None else element, "label", f"Disk {key}"),
                "controller": _child_text(element, "controllerKey"),
                "unit": _child_text(element, "unitNumber"),
            })
        elif ("Ethernet" in kind or kind in {"VirtualVmxnet", "VirtualVmxnet2", "VirtualVmxnet3", "VirtualPCNet32"}) and key:
            info, backing = _child(element, "deviceInfo"), _child(element, "backing")
            interfaces.append({
                "key": key,
                "label": _child_text(info if info is not None else element, "label", f"Network adapter {key}"),
                "network": _child_text(backing if backing is not None else element, "deviceName"),
            })
    for disk in disks:
        bus = controllers.get(disk["controller"])
        disk["instance"] = f"scsi{bus}:{disk['unit']}" if bus and disk["unit"] else disk["key"]
    return disks, interfaces


def _guest_filesystems(value: ET.Element | None) -> list[dict]:
    """GuestDiskInfo is available only when VMware Tools exposes it."""
    if value is None:
        return []
    filesystems: list[dict] = []
    for element in value.iter():
        path = _child_text(element, "diskPath")
        if path and path not in {item["path"] for item in filesystems}:
            filesystems.append({"path": path, "capacity": _child_text(element, "capacity"), "free": _child_text(element, "freeSpace")})
    return filesystems


def _snapshot_details(value: ET.Element | None) -> tuple[int, str]:
    if value is None:
        return 0, ""
    dates = [_child_text(item, "createTime") for item in value.iter() if _child(item, "createTime") is not None]
    return len(dates), max(dates, default="")


def _property_objects(root: ET.Element) -> list[tuple[str, dict[str, str]]]:
    objects: list[tuple[str, dict[str, str]]] = []
    for obj in root.iter():
        if _local(obj) != "objects":
            continue
        reference = _child_text(obj, "obj")
        if not reference:
            continue
        values: dict[str, str] = {}
        for prop in obj:
            if _local(prop) != "propSet":
                continue
            key = _child_text(prop, "name")
            value = _child_text(prop, "val")
            if key:
                values[key] = value
        objects.append((reference, values))
    return objects


def _parse_virtual_machines(root: ET.Element) -> list[dict]:
    virtual_machines: list[dict] = []
    for obj in root.iter():
        if _local(obj) != "objects":
            continue
        reference = _child_text(obj, "obj")
        if not reference:
            continue
        values: dict[str, str] = {}
        complex_values: dict[str, ET.Element] = {}
        for prop in obj:
            if _local(prop) != "propSet":
                continue
            key = _child_text(prop, "name")
            val = _child(prop, "val")
            if not key:
                continue
            values[key] = val.text.strip() if val is not None and val.text else ""
            if key in {"guest.disk", "config.hardware.device", "rootSnapshotList"}:
                complex_values[key] = val
        if values.get("config.template", "false").lower() == "true":
            continue
        power_state = values.get("runtime.powerState", "unknown")
        disks, interfaces = _hardware_devices(complex_values.get("config.hardware.device"))
        snapshot_count, snapshot_latest = _snapshot_details(complex_values.get("rootSnapshotList"))
        virtual_machines.append({
            "moid": reference,
            "name": values.get("name", reference),
            "address": values.get("guest.ipAddress") or f"vmware://{reference}",
            "power_state": power_state.removeprefix("powered").removeprefix("POWERED_"),
            "guest_os": values.get("guest.guestFullName") or values.get("config.guestFullName", ""),
            "properties": values,
            "disks": disks,
            "interfaces": interfaces,
            "filesystems": _guest_filesystems(complex_values.get("guest.disk")),
            "snapshot_count": snapshot_count,
            "snapshot_latest": snapshot_latest,
        })
    return virtual_machines


def _parse_host_systems(root: ET.Element) -> list[dict]:
    return [{"moid": reference, "name": values.get("name", reference), "properties": values} for reference, values in _property_objects(root)]


def _property_collection(
    client: _VimSoapClient, content: dict[str, str], entity_type: str, paths: tuple[str, ...]
) -> list[ET.Element]:
    """Return all result pages for a container view, including large vCenter inventories."""
    view = _container_view(client, content["viewManager"], content["rootFolder"], entity_type)
    pages: list[ET.Element] = []
    try:
        page = _property_page(client, content["propertyCollector"], view, entity_type, paths)
        pages.append(page)
        token = _text(page, "token")
        while token:
            page = _property_page(client, content["propertyCollector"], view, entity_type, paths, token)
            pages.append(page)
            token = _text(page, "token")
        return pages
    finally:
        try:
            client.call(f'<DestroyView xmlns="{VIM_NS}"><_this type="ContainerView">{escape(view)}</_this></DestroyView>')
        except Exception:
            pass


def _performance_counters(client: _VimSoapClient, content: dict[str, str]) -> dict[str, tuple[str, str]]:
    """Read available counter ids once.  IDs differ between ESXi versions."""
    manager = content.get("perfManager")
    if not manager:
        return {}
    root = client.call(
        f'<RetrievePropertiesEx xmlns="{VIM_NS}"><_this type="PropertyCollector">{escape(content["propertyCollector"])}</_this><specSet>'
        f'<propSet><type>PerformanceManager</type><pathSet>perfCounter</pathSet></propSet><objectSet>'
        f'<obj type="PerformanceManager">{escape(manager)}</obj><skip>false</skip></objectSet></specSet>'
        '<options><maxObjects>10</maxObjects></options></RetrievePropertiesEx>'
    )
    counters: dict[str, tuple[str, str]] = {}
    for prop in root.iter():
        if _local(prop) != "propSet" or _child_text(prop, "name") != "perfCounter":
            continue
        container = _child(prop, "val")
        if container is None:
            continue
        counter_nodes = [container] if _child(container, "key") is not None else list(container)
        for counter in counter_nodes:
            key = _child_text(counter, "key")
            group = _child(counter, "groupInfo")
            name = _child(counter, "nameInfo")
            rollup = _child_text(counter, "rollupType")
            unit_info = _child(counter, "unitInfo")
            unit = _child_text(unit_info if unit_info is not None else counter, "key")
            if key and group is not None and name is not None:
                counters[f"{_child_text(group, 'key')}.{_child_text(name, 'key')}.{rollup}"] = (key, unit)
    return counters


# A focused, portable subset of the official Zabbix VMware Guest counters.  It
# intentionally contains only counters that can be queried directly from both
# standalone ESXi and vCenter through the public SOAP API.
PERFORMANCE_KEYS = {
    "cpu.usage.average": "vmware.vm.cpu.usage_percent",
    "cpu.ready.summation": "vmware.vm.cpu.ready_ms",
    "cpu.wait.summation": "vmware.vm.cpu.wait_ms",
    "cpu.costop.summation": "vmware.vm.cpu.costop_ms",
    "mem.usage.average": "vmware.vm.memory.usage_percent",
    "mem.active.average": "vmware.vm.memory.active",
    "mem.swapinRate.average": "vmware.vm.memory.swap_in_rate",
    "mem.swapoutRate.average": "vmware.vm.memory.swap_out_rate",
    "net.usage.average": "vmware.vm.net.usage",
    "net.received.average": "vmware.vm.net.received",
    "net.transmitted.average": "vmware.vm.net.transmitted",
    "disk.usage.average": "vmware.vm.disk.usage",
    "disk.read.average": "vmware.vm.disk.read",
    "disk.write.average": "vmware.vm.disk.write",
    "disk.totalReadLatency.average": "vmware.vm.disk.read_latency",
    "disk.totalWriteLatency.average": "vmware.vm.disk.write_latency",
}

DISK_PERFORMANCE = {
    "disk.read.average": ("read_bps", "Average number of bytes read from the disk", "Bps"),
    "disk.write.average": ("write_bps", "Average number of bytes written to the disk", "Bps"),
    "disk.numberReadAveraged.average": ("read_iops", "Average number of reads from the disk", ""),
    "disk.numberWriteAveraged.average": ("write_iops", "Average number of writes to the disk", ""),
    "disk.queueRead.average": ("queue_read", "Average number of outstanding read requests to the disk", ""),
    "disk.queueWrite.average": ("queue_write", "Average number of outstanding write requests to the disk", ""),
    "disk.totalReadLatency.average": ("read_latency", "Average read latency from the disk", "ms"),
    "disk.totalWriteLatency.average": ("write_latency", "Average write latency to the disk", "ms"),
}

NETWORK_PERFORMANCE = {
    "net.usage.average": ("usage", "Network utilization on interface", "Bps"),
    "net.received.average": ("received", "Number of bytes received on interface", "Bps"),
    "net.transmitted.average": ("transmitted", "Number of bytes transmitted on interface", "Bps"),
    "net.packetsRx.summation": ("packets_rx", "Number of packets received on interface", ""),
    "net.packetsTx.summation": ("packets_tx", "Number of packets transmitted on interface", ""),
}


def _scale_performance(value: str, unit: str) -> str:
    try:
        number = float(value)
    except ValueError:
        return value
    if unit == "percent":
        number /= 100
    elif unit in {"kiloBytesPerSecond", "kiloBytes"}:
        number *= 1024
    return str(round(number, 3)).rstrip("0").rstrip(".") if "." in str(round(number, 3)) else str(int(number))


def _performance_values(client: _VimSoapClient, content: dict[str, str], virtual_machines: list[dict]) -> None:
    """Populate VM records with the latest real-time values where supported.

    Some ESXi editions do not expose every counter.  Missing counters are
    simply omitted; inventory discovery must never fail because a performance
    counter is unavailable.
    """
    try:
        counters = _performance_counters(client, content)
        selected = [(path, *counters[path]) for path in PERFORMANCE_KEYS if path in counters]
        if not counters or not virtual_machines:
            return
        queries = []
        expected: dict[tuple[str, str, str], dict] = {}
        for vm in virtual_machines:
            ids: list[tuple[str, str, str, dict]] = []
            for path, counter_id, unit in selected:
                ids.append((counter_id, "", unit, {"target": "base", "key": PERFORMANCE_KEYS[path]}))
            for disk in vm.get("disks") or []:
                for path, (suffix, title, units) in DISK_PERFORMANCE.items():
                    if path in counters:
                        counter_id, unit = counters[path]
                        identifier = str(disk["key"])
                        ids.append((counter_id, str(disk["instance"]), unit, {
                            "target": "dynamic", "key": f"vmware.vm.disk.{suffix}[{identifier}]",
                            "name": f"{title} [{disk['label']}]", "oid": f"vmware://perf/disk/{disk['instance']}/{path}", "units": units,
                        }))
            for interface in vm.get("interfaces") or []:
                for path, (suffix, title, units) in NETWORK_PERFORMANCE.items():
                    if path in counters:
                        counter_id, unit = counters[path]
                        identifier = str(interface["key"])
                        label = f"[{interface['network'] or 'network'}]/[{interface['label']}]"
                        ids.append((counter_id, identifier, unit, {
                            "target": "dynamic", "key": f"vmware.vm.net.{suffix}[{identifier}]",
                            "name": f"{title} {label}", "oid": f"vmware://perf/net/{identifier}/{path}", "units": units,
                        }))
            metrics = "".join(
                f"<metricId><counterId>{escape(counter_id)}</counterId><instance>{escape(instance)}</instance></metricId>"
                for counter_id, instance, _, _ in ids
            )
            for counter_id, instance, unit, definition in ids:
                expected[(vm["moid"], counter_id, instance)] = {**definition, "counter_unit": unit}
            queries.append(
                f'<querySpec><entity type="VirtualMachine">{escape(vm["moid"])}</entity>{metrics}'
                "<intervalId>20</intervalId><maxSample>1</maxSample></querySpec>"
            )
        root = client.call(
            f'<QueryPerf xmlns="{VIM_NS}"><_this type="PerformanceManager">{escape(content["perfManager"])}</_this>'
            f"{''.join(queries)}</QueryPerf>"
        )
        by_moid = {vm["moid"]: vm for vm in virtual_machines}
        for result in root.iter():
            if _local(result) != "returnval":
                continue
            entity = _child_text(result, "entity")
            vm = by_moid.get(entity)
            if not vm:
                continue
            perf = vm.setdefault("performance", {})
            for series in result:
                if _local(series) != "value":
                    continue
                identifier = _child(series, "id")
                counter_id = _child_text(identifier if identifier is not None else series, "counterId")
                instance = _child_text(identifier if identifier is not None else series, "instance")
                definition = expected.get((entity, counter_id, instance))
                values = [child.text.strip() for child in series if _local(child) == "value" and child.text]
                if definition and values:
                    value = _scale_performance(values[-1], definition["counter_unit"])
                    if definition["target"] == "base":
                        perf[definition["key"]] = value
                    else:
                        vm.setdefault("dynamic_metrics", []).append({
                            "key": definition["key"], "name": definition["name"], "oid": definition["oid"],
                            "units": definition["units"], "value": value,
                        })
    except Exception:
        # A user can still monitor inventory/configuration if PerformanceManager
        # is disabled by a VMware edition or a restrictive API privilege.
        return


def _soap_inventory(address: str, credentials: dict) -> VMwareResult:
    client = _VimSoapClient(address, credentials)
    content: dict[str, str] = {}
    try:
        content = _service_content(client)
        _login(client, content["sessionManager"], credentials)
        virtual_machines = [vm for page in _property_collection(client, content, "VirtualMachine", VM_PROPERTIES) for vm in _parse_virtual_machines(page)]
        host_systems = [host for page in _property_collection(client, content, "HostSystem", HOST_PROPERTIES) for host in _parse_host_systems(page)]
        _performance_values(client, content, virtual_machines)
        return VMwareResult(
            True,
            product=f"vSphere SOAP {content['apiVersion']}",
            virtual_machines=virtual_machines,
            host_systems=host_systems,
        )
    except Exception as exc:
        return VMwareResult(False, error=_error(exc))
    finally:
        if content.get("sessionManager") and client.cookie:
            try:
                client.call(f'<Logout xmlns="{VIM_NS}"><_this type="SessionManager">{escape(content["sessionManager"])}</_this></Logout>')
            except Exception:
                pass


def _error(exc: Exception) -> str:
    text = str(exc).replace("\n", " ").strip()
    return (text or "Не удалось подключиться к VMware API")[:700]


def test_vmware(address: str, credentials: dict) -> VMwareResult:
    result = _soap_inventory(address, credentials)
    return VMwareResult(result.ok, product=result.product, error=result.error)


def discover_virtual_machines(address: str, credentials: dict) -> VMwareResult:
    """Read ESXi/vCenter VM inventory using VMware's SOAP inventory API."""
    return _soap_inventory(address, credentials)
