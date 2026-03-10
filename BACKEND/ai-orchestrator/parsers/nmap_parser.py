"""Nmap XML parser used by the unified analysis engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from xml.etree import ElementTree


@dataclass(frozen=True)
class PortFinding:
    """Normalized port-level finding from Nmap output."""

    port: int
    protocol: str
    state: str
    reason: str | None
    service: str | None
    product: str | None
    version: str | None


@dataclass(frozen=True)
class HostFinding:
    """Normalized host-level finding from Nmap output."""

    address: str
    status: str
    hostname: str | None
    ports: list[PortFinding] = field(default_factory=list)
    os_matches: list[str] = field(default_factory=list)
    host_scripts: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class NmapScanResult:
    """Top-level parsed Nmap scan data."""

    command: str
    nmap_version: str
    elapsed_seconds: float
    hosts: list[HostFinding]


class NmapParser:
    """Parser for Nmap XML output."""

    @staticmethod
    def parse(xml_content: str) -> NmapScanResult:
        """Parse Nmap XML content into typed dataclasses.

        Args:
            xml_content: Raw XML output produced by ``nmap -oX -``.

        Returns:
            A normalized ``NmapScanResult`` structure.
        """

        root = ElementTree.fromstring(xml_content)
        run_attrs = root.attrib
        command = run_attrs.get("args", "")
        nmap_version = run_attrs.get("version", "unknown")

        elapsed_seconds = 0.0
        finished = root.find("./runstats/finished")
        if finished is not None:
            elapsed_text = finished.attrib.get("elapsed", "0")
            try:
                elapsed_seconds = float(elapsed_text)
            except ValueError:
                elapsed_seconds = 0.0

        hosts: list[HostFinding] = []
        for host in root.findall("host"):
            hosts.append(NmapParser._parse_host(host))

        return NmapScanResult(
            command=command,
            nmap_version=nmap_version,
            elapsed_seconds=elapsed_seconds,
            hosts=hosts,
        )

    @staticmethod
    def _parse_host(host: ElementTree.Element) -> HostFinding:
        status = host.find("status")
        state = status.attrib.get("state", "unknown") if status is not None else "unknown"

        address = "unknown"
        for address_node in host.findall("address"):
            if address_node.attrib.get("addrtype") == "ipv4":
                address = address_node.attrib.get("addr", "unknown")
                break

        hostname: str | None = None
        hostname_node = host.find("./hostnames/hostname")
        if hostname_node is not None:
            hostname = hostname_node.attrib.get("name")

        ports: list[PortFinding] = []
        for port in host.findall("./ports/port"):
            ports.append(NmapParser._parse_port(port))

        os_matches = [
            os_match.attrib.get("name", "unknown")
            for os_match in host.findall("./os/osmatch")
        ]

        scripts = [
            script.attrib.get("id", "")
            for script in host.findall("./hostscript/script")
            if script.attrib.get("id")
        ]

        return HostFinding(
            address=address,
            status=state,
            hostname=hostname,
            ports=ports,
            os_matches=os_matches,
            host_scripts=scripts,
        )

    @staticmethod
    def _parse_port(port: ElementTree.Element) -> PortFinding:
        port_id = int(port.attrib.get("portid", "0"))
        protocol = port.attrib.get("protocol", "tcp")

        state_node = port.find("state")
        state = state_node.attrib.get("state", "unknown") if state_node is not None else "unknown"
        reason = state_node.attrib.get("reason") if state_node is not None else None

        service_node = port.find("service")
        service: dict[str, Any] = service_node.attrib if service_node is not None else {}

        return PortFinding(
            port=port_id,
            protocol=protocol,
            state=state,
            reason=reason,
            service=service.get("name"),
            product=service.get("product"),
            version=service.get("version"),
        )
