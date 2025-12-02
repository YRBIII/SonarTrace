import argparse
import ipaddress
from typing import List
from .nmap_handler import NmapHandler, NmapExecutionError
from .nmap_parser import NmapParser
from .report_builder import ReportBuilder
from .windows_enum import WindowsEnumerator
from  .import __version__, __app_name__


ASCII_BANNER = r"""
  _________                       ___________                     
 /   _____/ ____   ____   ____   \__    ___/______   ____   ______
 \_____  \\_/ __ \\_/ __ \\_/ __ \\    |    |  \_  __ \\_/ __ \\ /  ___/
 /        \\  ___/\\  ___/\\  ___/    |    |   |  | \\  ___/ \\___ \\ 
/_______  / \\___  >\\___  >\\___  >   |____|   |__|   \\___  >____  >              
        \\/      \\/     \\/     \\/                         \\/     \\/ 

        
    / \'._   (\_/)   _.'/ \       (_                   _)
   / .''._'--(o.o)--'_.''. \       /\                 /\
  /.' _/ |`'=/ " \='`| \_ `.\     / \'._   (\_/)   _.'/ \
 /` .' `\;-,'\___/',-;/` '. '\   /_.''._'--('.')--'_.''._\
/.-' jgs   `\(-V-)/`       `-.\  | \_ / `;=/ " \=;` \ _/ |
             "   "               \/  `\__|`\___/`|__/`  \/
                                  `       \(/|\)/       `
                                           " ` "

  SonarTrace - focused Nmap wrapper for *authorized* assessments only.
"""


def _looks_like_ip(target: str) -> bool:
    try:
        # ipaddress also understands CIDR ranges
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False


def _validate_targets(targets: List[str], allow_dns: bool) -> None:
    if allow_dns:
        return

    non_ip = [t for t in targets if not _looks_like_ip(t)]
    if non_ip:
        raise SystemExit(
            "Refusing to resolve hostnames because DNS leakage could identify your scan.\n"
            "Either specify IP addresses / CIDR ranges only, or pass --allow-dns if you "
            "understand and accept the risk. Offending values: " + ", ".join(non_ip)
        )

    for t in targets:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            continue
        if net.prefixlen < 8:
            raise SystemExit(
                f"Target {t} is overly broad (prefix {net.prefixlen}). For safety, SonarTrace "
                "requires a prefix length of /8 or smaller (e.g., 10.0.0.0/16, 192.168.0.0/24)."
            )


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=__app_name__,
        description=(
            "SonarTrace is a thin wrapper around Nmap that focuses on safe defaults, basic "
            "parsing, and human‑readable reports. Only use it against systems you are "
            "explicitly authorized to test."
        ),
    )
    p.add_argument(
        "targets",
        nargs="+",
        help="List of target IPs / CIDR ranges (or hostnames if --allow-dns is set)."
    )
    p.add_argument(
        "-p", "--ports",
        help="Port specification in Nmap format (e.g. 1-1024,80,443). If omitted, Nmap defaults apply."
    )
    p.add_argument(
        "-o", "--output",
        help="Path to write the text report to. If omitted, prints to stdout."
    )
    p.add_argument(
        "--json-output",
        help="Optional path for a JSON report (in addition to the text report)."
    )
    p.add_argument(
        "--rate", type=int, default=None,
        help="Rough rate control. Values <= 2000 imply a more polite Nmap timing template."
    )
    p.add_argument(
        "-x", "--exclude", action="append", default=[],
        help="Host(s) or network(s) to exclude from the scan. Can be used multiple times."
    )
    p.add_argument(
        "--allow-dns", action="store_true",
        help="Allow DNS resolution of hostnames (disables the DNS leakage safety check)."
    )
    p.add_argument(
        "--nmap-arg", dest="nmap_args", action="append", default=[],
        help="Additional raw nmap arguments to append (advanced use only)."
    )
    p.add_argument(
        "--version", action="version",
        version=f"%(prog)s {__version__}",
    )
    return p


def main(argv: list[str] | None = None) -> None:
    print(ASCII_BANNER)
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    # Very explicit legality warning
    print("[!] Use this tool ONLY against hosts and networks you are explicitly authorized to test.")
    print("[!] The authors take no responsibility for misuse.\n" )

    _validate_targets(args.targets, allow_dns=args.allow_dns)

    handler = NmapHandler(
        targets=args.targets,
        ports=args.ports,
        rate_limit=args.rate,
        extra_args=args.nmap_args,
        excludes=args.exclude,
    )

    try:
        xml_output = handler.run_scan()
    except NmapExecutionError as e:
        parser.exit(status=1, message=f"[!] Nmap error: {e}\n" )

    parser_obj = NmapParser()
    hosts = parser_obj.parse(xml_output)

    win_enum = WindowsEnumerator()
    win_enum.enumerate(hosts)

    metadata = {
        "targets": ", ".join(args.targets),
        "excluded": ", ".join(args.exclude) if args.exclude else "(none)",
    }
    builder = ReportBuilder(metadata=metadata)
    text_report = builder.build_text_report(hosts)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text_report)
        print(f"[+] Text report written to {args.output}")
    else:
        print(text_report)

    if args.json_output:
        json_report = builder.build_json_report(hosts)
        with open(args.json_output, "w", encoding="utf-8") as f:
            f.write(json_report)
        print(f"[+] JSON report written to {args.json_output}")


if __name__ == "__main__":  # pragma: no cover
    main()