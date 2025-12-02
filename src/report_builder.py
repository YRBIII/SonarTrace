import json
from typing import Iterable, Dict, Any
from datetime import datetime
from .result_objects import HostResult, PortInfo


class ReportBuilder:
    """Builds text and JSON reports from scan results."""

    def __init__(self, metadata: Dict[str, Any] | None = None) -> None:
        self.metadata = metadata or {}

    def _host_header(self, host: HostResult) -> str:
        name_part = f" ({host.hostname})" if host.hostname else ""
        os_part = f" | OS: {host.os_name} ({host.os_accuracy or '?'}%)" if host.os_name else ""
        return f"Host: {host.ip}{name_part} | Status: {host.status}{os_part}"

    def build_text_report(self, hosts: Iterable[HostResult]) -> str:
        lines: list[str] = []
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        lines.append("SonarTrace Scan Report")
        lines.append("=" * 60)
        lines.append(f"Generated: {now}")
        if self.metadata:
            for k, v in self.metadata.items():
                lines.append(f"{k}: {v}")
        lines.append("" )

        for host in hosts:
            lines.append(self._host_header(host))
            if not host.is_up:
                lines.append("  Host appears to be down or filtered.")
                lines.append("" )
                continue

            if host.ports:
                lines.append("  Open / filtered ports:")
                lines.append("    PORT    STATE     SERVICE        PRODUCT / VERSION")
                for p in sorted(host.ports, key=lambda x: (x.port, x.protocol)):
                    svc = p.service or "?"
                    prod = p.product or ""
                    ver = p.version or ""
                    prod_ver = (prod + " " + ver).strip()
                    lines.append(
                        f"    {p.port:>5}/{p.protocol:<3}  {p.state:<9} {svc:<13} {prod_ver}"
                    )
            else:
                lines.append("  No open ports reported by Nmap.")

            if host.scripts:
                lines.append("" )
                lines.append("  Script / advisory output:")
                for sid, out in host.scripts.items():
                    lines.append(f"    [{sid}]" )
                    for ln in out.splitlines():
                        lines.append(f"      {ln}" )

            lines.append("" )

        return "\n".join(lines)

    def build_json_report(self, hosts: Iterable[HostResult]) -> str:
        def port_to_dict(p: PortInfo) -> Dict[str, Any]:
            return {
                "port": p.port,
                "protocol": p.protocol,
                "state": p.state,
                "reason": p.reason,
                "service": p.service,
                "product": p.product,
                "version": p.version,
            }

        data: Dict[str, Any] = {
            "generated_utc": datetime.utcnow().isoformat() + "Z",
            "metadata": self.metadata,
            "hosts": [],
        }

        for h in hosts:
            data["hosts"].append(
                {
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "status": h.status,
                    "os_name": h.os_name,
                    "os_accuracy": h.os_accuracy,
                    "is_windows": h.is_windows,
                    "ports": [port_to_dict(p) for p in h.ports],
                    "scripts": h.scripts,
                }
            )

        return json.dumps(data, indent=2)