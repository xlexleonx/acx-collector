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
    fields = ("rootFolder", "viewManager", "propertyCollector", "sessionManager")
    values = {field: _text(root, field) for field in fields}
    if not all(values.values()):
        raise RuntimeError("VMware SOAP не вернул служебные объекты API")
    values["apiVersion"] = _text(root, "apiVersion", "vSphere SOAP")
    return values


def _login(client: _VimSoapClient, session_manager: str, credentials: dict) -> None:
    client.call(
        f'<Login xmlns="{VIM_NS}"><_this type="SessionManager">{escape(session_manager)}</_this>'
        f"<userName>{escape(str(credentials.get('username') or ''))}</userName>"
        f"<password>{escape(str(credentials.get('password') or ''))}</password></Login>"
    )


def _container_view(client: _VimSoapClient, view_manager: str, root_folder: str) -> str:
    root = client.call(
        f'<CreateContainerView xmlns="{VIM_NS}"><_this type="ViewManager">{escape(view_manager)}</_this>'
        f'<container type="Folder">{escape(root_folder)}</container><type>VirtualMachine</type><recursive>true</recursive>'
        "</CreateContainerView>"
    )
    view = _text(root, "returnval")
    if not view:
        raise RuntimeError("VMware SOAP не создал представление виртуальных машин")
    return view


def _property_page(client: _VimSoapClient, property_collector: str, container_view: str, token: str = "") -> ET.Element:
    if token:
        return client.call(
            f'<ContinueRetrievePropertiesEx xmlns="{VIM_NS}"><_this type="PropertyCollector">{escape(property_collector)}</_this>'
            f"<token>{escape(token)}</token></ContinueRetrievePropertiesEx>"
        )
    paths = "".join(f"<pathSet>{path}</pathSet>" for path in (
        "name", "runtime.powerState", "guest.ipAddress", "config.guestFullName", "config.template"
    ))
    return client.call(
        f'<RetrievePropertiesEx xmlns="{VIM_NS}"><_this type="PropertyCollector">{escape(property_collector)}</_this><specSet>'
        f"<propSet><type>VirtualMachine</type>{paths}</propSet><objectSet>"
        f'<obj type="ContainerView">{escape(container_view)}</obj><skip>false</skip>'
        '<selectSet xsi:type="TraversalSpec"><name>viewTraversal</name><type>ContainerView</type><path>view</path><skip>false</skip></selectSet>'
        "</objectSet></specSet><options><maxObjects>1000</maxObjects></options></RetrievePropertiesEx>"
    )


def _parse_virtual_machines(root: ET.Element) -> list[dict]:
    virtual_machines: list[dict] = []
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
        if values.get("config.template", "false").lower() == "true":
            continue
        power_state = values.get("runtime.powerState", "unknown")
        virtual_machines.append({
            "moid": reference,
            "name": values.get("name", reference),
            "address": values.get("guest.ipAddress") or f"vmware://{reference}",
            "power_state": power_state.removeprefix("powered").removeprefix("POWERED_"),
            "guest_os": values.get("config.guestFullName", ""),
        })
    return virtual_machines


def _soap_inventory(address: str, credentials: dict) -> VMwareResult:
    client = _VimSoapClient(address, credentials)
    content: dict[str, str] = {}
    container_view = ""
    try:
        content = _service_content(client)
        _login(client, content["sessionManager"], credentials)
        container_view = _container_view(client, content["viewManager"], content["rootFolder"])
        root = _property_page(client, content["propertyCollector"], container_view)
        virtual_machines = _parse_virtual_machines(root)
        token = _text(root, "token")
        while token:
            root = _property_page(client, content["propertyCollector"], container_view, token)
            virtual_machines.extend(_parse_virtual_machines(root))
            token = _text(root, "token")
        return VMwareResult(True, product=f"vSphere SOAP {content['apiVersion']}", virtual_machines=virtual_machines)
    except Exception as exc:
        return VMwareResult(False, error=_error(exc))
    finally:
        if container_view:
            try:
                client.call(f'<DestroyView xmlns="{VIM_NS}"><_this type="ContainerView">{escape(container_view)}</_this></DestroyView>')
            except Exception:
                pass
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
