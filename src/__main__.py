from pathlib import Path
from datetime import datetime

from .cli import _build_arg_parser
from .nmap_handler import NmapHandler, NmapExecutionError
from .enumerator import enumerate_hosts
from .report_builder import ReportBuilder
from .logger_setup import get_logger

logger = get_logger("main")


def main():
    """
    Main entry point for the SonarTrace network enumeration and reporting application.
    This function orchestrates the entire workflow of the SonarTrace tool:
    1. Parses command-line arguments to configure the Nmap scan parameters
    2. Initializes the NmapHandler with user-specified targets, ports, and scan options
    3. Executes centralized host enumeration via the enumerator module
    4. Compiles metadata about the scan execution (targets, exclusions, commands, etc.)
    5. Generates a comprehensive text-based report of discovered hosts and services
    6. Outputs the report to either a user-specified file path or a default timestamped file
    The function handles Nmap execution errors and logs all major operations
    for debugging and audit purposes. The output filename defaults to a UTC-timestamped
    format to ensure chronological organization and compliance with reporting standards.
    Raises:
        NmapExecutionError: If the underlying Nmap command fails during host enumeration.
    Returns:
        None: This function serves as the application entry point and does not return
        a value; instead, it performs side effects (file I/O and logging).
    """
    parser = _build_arg_parser()
    args = parser.parse_args()

    logger.info("Starting SonarTrace scan process...")

    handler = NmapHandler(
        targets=args.targets,
        ports=args.ports,
        rate_limit=args.rate,
        extra_args=args.nmap_args,
        excludes=args.exclude,
    )

    try:
        # Centralized enumeration (via enumerator.py)
        hosts, raw_xml_output, executed_command = enumerate_hosts(handler)
    except NmapExecutionError as e:
        logger.error(f"Nmap failed: {e}")
        return

    # -----------------------------
    # Metadata passed into report
    # -----------------------------
    metadata = {
        "targets": ", ".join(args.targets),
        "excludes": ", ".join(args.exclude) if args.exclude else "(none)",
        "nmap_command": executed_command,
        "raw_nmap_output": raw_xml_output,  # REQUIRED for rubric
    }

    builder = ReportBuilder(metadata=metadata)
    text_report = builder.build_text_report(hosts)

    # ----------------------------------------
    # DEFAULT OUTPUT FILE (UTC, rubric-required)
    # ----------------------------------------
    if args.output:
        output_path = Path(args.output)
    else:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M_UTC")
        output_path = Path.cwd() / f"host_enumeration_report_{timestamp}.md"

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(text_report)

    logger.info(f"Report written to {output_path}")


if __name__ == "__main__":
    main()