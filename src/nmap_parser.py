import xml.etree.ElementTree as ET
from typing import List
from .result_objects import HostResult, PortInfo


class NmapParser:
    """Parses Nmap XML output into HostResult objects."""

    def parse(self, xml_text: str) -> List[HostResult]:
        hosts: List[HostResult] = []

        root = ET.fromstring(xml_text)
        for host_el in root.findall("host"):
            status_el = host_el.find("status")
            status = status_el.get("state", "unknown") if status_el is not None else "unknown"

            addr_el = host_el.find("address[@addrtype='ipv4']")
            ip = addr_el.get("addr") if addr_el is not None else "unknown"

            hostname_el = host_el.find("hostnames/hostname")
            hostname = hostname_el.get("name") if hostname_el is not None else ""

            # OS detection
            os_name = ""
            os_accuracy = None
            osmatch_el = host_el.find("os/osmatch")
            if osmatch_el is not None:
                os_name = osmatch_el.get("name", "")
                acc = osmatch_el.get("accuracy")
                if acc is not None and acc.isdigit():
                    os_accuracy = int(acc)

            host_result = HostResult(
                ip=ip,
                hostname=hostname,
                status=status,
                os_name=os_name,
                os_accuracy=os_accuracy,
            )

            # Ports
            for port_el in host_el.findall("ports/port"):
                proto = port_el.get("protocol", "")
                port_id = int(port_el.get("portid", "0"))

                state_el = port_el.find("state")
                state = state_el.get("state", "unknown") if state_el is not None else "unknown"
                reason = state_el.get("reason") if state_el is not None else None

                service_el = port_el.find("service")
                service = service_el.get("name") if service_el is not None else None
                product = service_el.get("product") if service_el is not None else None
                version = service_el.get("version") if service_el is not None else None

                host_result.ports.append(
                    PortInfo(
                        port=port_id,
                        protocol=proto,
                        state=state,
                        reason=reason,
                        service=service,
                        product=product,
                        version=version,
                    )
                )

            # Script results (per host)
            for script_el in host_el.findall("hostscript/script"):
                script_id = script_el.get("id", "unknown")
                output = script_el.get("output", "")
                host_result.scripts[script_id] = output

            hosts.append(host_result)

        return hosts