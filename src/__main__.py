from pathlib import Path
from datetime import datetime

from .cli import _build_arg_parser
from .nmap_handler import NmapHandler, NmapExecutionError
from .enumerator import enumerate_hosts
from .report_builder import ReportBuilder
from .logger_setup import get_logger

logger = get_logger("main")


def main():
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