import argparse

from audit_pkg.scanner import FileScanner
from audit_pkg.report import generate_summary_report
from audit_pkg.logger import get_logger
from audit_pkg.utils import export_json_report, write_json_to_file


logger = get_logger()


def scan_command(path, json_file=None):
    logger.info(f"Starting audit scan on path: {path}")

    scanner = FileScanner(path)
    results = scanner.scan()

    # Console report
    report = generate_summary_report(results)
    print(report)

    # Optional JSON export
    if json_file:
        json_data = export_json_report(path, results)
        write_json_to_file(json_file, json_data)
        logger.info(f"JSON report written to {json_file}")

    logger.info("Audit scan completed")


def main():
    parser = argparse.ArgumentParser(
        description="Linux Security Audit CLI"
    )

    subparsers = parser.add_subparsers(dest="command")

    # Scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan directory for security risks"
    )
    scan_parser.add_argument(
        "--path",
        required=True,
        help="Directory path to scan"
    )
    scan_parser.add_argument(
        "--json",
        help="Export results to JSON file"
    )

    args = parser.parse_args()

    if args.command == "scan":
        scan_command(args.path, args.json)
    else:
        parser.print_help()