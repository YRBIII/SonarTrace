"""
result_objects.py

Basic data classes used to store host and port information for SonarTrace.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class PortInfo:
    """Stores information about a single scanned port."""
    port: int                  # Port number
    protocol: str              # tcp or udp
    state: str                 # open, closed, filtered, etc.
    reason: Optional[str] = None    # Why Nmap thinks it's in that state
    service: Optional[str] = None   # Service name (http, ssh...)
    product: Optional[str] = None   # Detected software
    version: Optional[str] = None   # Version, if Nmap finds one


@dataclass
class HostResult:
    """Stores all scan results for a single host."""
    ip: str                    # Host IP address
    hostname: str              # Hostname from DNS or reverse lookup
    status: str                # up or down
    os_name: str = ""          # OS guess from Nmap
    os_accuracy: Optional[int] = None  # Confidence level

    ports: List[PortInfo] = field(default_factory=list)  # List of open ports
    scripts: Dict[str, str] = field(default_factory=dict)  # Script output

    @property
    def is_up(self) -> bool:
        """True if Nmap reports the host is up."""
        return self.status.lower() == "up"

    @property
    def is_windows(self) -> bool:
        """Simple check for Windows systems."""
        if not self.os_name:
            return False
        return "windows" in self.os_name.lower()
