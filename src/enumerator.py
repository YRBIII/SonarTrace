"""
enumerator.py – Central enumeration orchestrator for SonarTrace.

This module coordinates:
- Target handling
- Nmap execution
- XML parsing
- Windows-specific enumeration

NOTE:
This file is intentionally used by __main__.py as the single
enumeration entry point to avoid duplicated scan logic.
"""

from typing import List, Tuple

from .nmap_handler import NmapHandler, NmapExecutionError
from .nmap_parser import NmapParser
from .windows_enum import WindowsEnumerator
from .logger_setup import get_logger

log = get_logger("enumerator")


def enumerate_hosts(
    handler: NmapHandler,
) -> Tuple[List, str, str]:
    """
    Runs the full enumeration pipeline and returns:
    - Parsed HostResult objects
    - Raw Nmap XML output
    - Exact Nmap command used (string)
    """

    log.info("Starting centralized enumeration pipeline")

    # Run Nmap once
    raw_xml_output = handler.run_scan()

    # Capture the exact command used (rubric requirement)
    executed_command = " ".join(handler.build_command())

    # Parse XML into HostResult objects
    parser = NmapParser()
    hosts = parser.parse(raw_xml_output)

    # Perform Windows-specific enumeration
    win_enum = WindowsEnumerator()
    win_enum.enumerate(hosts)

    log.info("Enumeration pipeline completed successfully")

    return hosts, raw_xml_output, executed_command