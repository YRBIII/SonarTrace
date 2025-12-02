from typing import List
from .result_objects import HostResult


class WindowsEnumerator:
    """Very light-weight placeholder for Windows-specific enumeration.

    In a real-world tool this might:
    - Run additional nmap NSE scripts (smb-os-discovery, smb-enum-shares, etc.)
    - Call external tools like `smbclient`, `rpcclient`, or `crackmapexec`

    For this project we keep it simple and just tag Windows hosts and return
    advisory text. The goal is to show *design* more than deep exploitation.
    """

    def enumerate(self, hosts: List[HostResult]) -> None:
        for host in hosts:
            if not host.is_windows or not host.is_up:
                continue

            note_lines = [
                f"Host {host.ip} appears to be Windows ({host.os_name}).",
                "Suggested follow‑up (manual) checks:",
                "  - Inspect SMB shares and SMB signing configuration.",
                "  - Review RDP exposure and authentication settings.",
                "  - Check for legacy protocols (SMBv1, LM/NTLM).",
                "  - Perform authenticated patch level review if credentials are available.",
            ]
            host.scripts.setdefault("sonartrace-windows-advice", "\n".join(note_lines))
