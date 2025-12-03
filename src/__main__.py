"""
__main__.py
Backend worker for SonarTrace.

This routes:
- CLI -> argument parsing
- NmapHandler -> raw scan execution
- NmapParser -> converting XML into Python objects
- ReportBuilder -> generating the Markdown report

This is the required modular design for the project.
"""

from .cli import _build_arg_parser
from .nmap_handler import NmapHandler, NmapExecutionError
from .nmap_parser import NmapParser
from .report_builder import ReportBuilder
from .windows_enum import WindowsEnumerator
from .logger_setup import get_logger

logger = get_logger("main")


def main():
    parser = _build_arg_parser()
    args = parser.parse_args()

    logger.info("Starting SonarTrace scan process...")

    # Builds an Nmap handler with CLI args
    handler = NmapHandler(
        targets=args.targets,
        ports=args.ports,
        rate_limit=args.rate,
        extra_args=args.nmap_args,
        excludes=args.exclude,
    )

    try:
        # Runs the scan and capture raw XML output
        raw_xml_output = handler.run_scan()
    except NmapExecutionError as e:
        logger.error(f"Nmap failed: {e}")
        return

    # Saves the exact command used (required for the report)
    executed_command = " ".join(handler.build_command())

    # Parses the XML into host objects
    parser_obj = NmapParser()
    hosts = parser_obj.parse(raw_xml_output)

    # Windows enumeration (optional)
    win_enum = WindowsEnumerator()
    win_enum.enumerate(hosts)

    # Prepare metadata for the report
    metadata = {
        "targets": ", ".join(args.targets),
        "excludes": ", ".join(args.exclude) if args.exclude else "(none)",
        "nmap_command": executed_command,
    }

    # Build the final report
    builder = ReportBuilder(metadata=metadata)
    text_report = builder.build_text_report(hosts)

    # Write output
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text_report)
        logger.info(f"Report written to {args.output}")
    else:
        print(text_report)


if __name__ == "__main__":
    main()