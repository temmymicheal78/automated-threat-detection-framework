#!/usr/bin/env python3
"""Automated Threat Detection System — Main Entry Point"""
from __future__ import annotations

import argparse
import csv
import logging
import sys
from pathlib import Path

# Ensure the project root (parent of this file's directory) is on sys.path so
# that "src.*" imports work whether the script is invoked as
#   python src/main.py          (from the project root)
# or as a module:
#   python -m src.main
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# On Windows the default console encoding is often cp1252, which cannot
# represent box-drawing characters used in the reporter summary.  Reconfigure
# stdout/stderr to UTF-8 so those characters print correctly.
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

# ---------------------------------------------------------------------------
# Logging helpers (must come before any src imports so the root logger is
# configured before module-level loggers are created in the imports below).
# ---------------------------------------------------------------------------

def setup_logging(level: str) -> None:
    """Configure the root logger with a standard timestamped format."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )


# ---------------------------------------------------------------------------
# Project imports
# ---------------------------------------------------------------------------

from src.config import load_config, Config  # noqa: E402
from src.log_parser import parse_log_file, tail_log_file  # noqa: E402
from src.detector import SlidingWindowDetector  # noqa: E402
from src.api_client import create_api_client  # noqa: E402
from src.multi_intel import create_multi_intel  # noqa: E402
from src.decision import DecisionEngine, Decision  # noqa: E402
from src.firewall import FirewallController  # noqa: E402
from src.reporter import Reporter  # noqa: E402
from src.database import ThreatDatabase  # noqa: E402
from src.notifier import EmailNotifier  # noqa: E402

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="threat-detector",
        description="Automated SSH brute-force detection and response system.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Batch mode with mock API\n"
            "  python src/main.py --no-api --log-file data/sample_logs/auth.log\n\n"
            "  # Watch mode, real API, dry-run\n"
            "  python src/main.py --watch --config config.json\n\n"
            "  # Live blocking (requires confirmation)\n"
            "  python src/main.py --live --config config.json\n"
        ),
    )

    parser.add_argument(
        "--config",
        metavar="PATH",
        default=None,
        help="Path to JSON or YAML configuration file.",
    )
    parser.add_argument(
        "--log-file",
        metavar="PATH",
        default=None,
        help="Override the log file path from config.",
    )
    parser.add_argument(
        "--report-file",
        metavar="PATH",
        default=None,
        help="Override the report output CSV path from config.",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        default=False,
        help="Real-time tail mode: continuously follow the log file (default: batch mode).",
    )

    # Dry-run / live mode are mutually exclusive
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Force dry-run mode — no real firewall changes (overrides config).",
    )
    mode_group.add_argument(
        "--live",
        action="store_true",
        default=False,
        help="Disable dry-run and perform real firewall blocks (requires confirmation).",
    )

    parser.add_argument(
        "--no-api",
        action="store_true",
        default=False,
        help="Use MockAbuseIPDBClient — skip real AbuseIPDB API calls.",
    )
    parser.add_argument(
        "--firewall-host",
        metavar="HOST",
        default=None,
        help="IP address of a remote firewall VM for SSH-based blocking.",
    )
    parser.add_argument(
        "--ground-truth",
        metavar="PATH",
        default=None,
        help="CSV file with columns ip,is_malicious (0 or 1) for accuracy metrics.",
    )
    parser.add_argument(
        "--log-level",
        metavar="LEVEL",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity: DEBUG | INFO | WARNING | ERROR (default: INFO).",
    )
    parser.add_argument(
        "--log-source",
        choices=["auth", "firewall"],
        default=None,
        help="Log format: 'auth' for SSH auth.log, 'firewall' for iptables kern.log (IPS mode).",
    )
    parser.add_argument(
        "--threshold",
        metavar="INT",
        type=int,
        default=None,
        help="Override fail_threshold from config.",
    )
    parser.add_argument(
        "--window",
        metavar="INT",
        type=int,
        default=None,
        help="Override window_seconds from config.",
    )
    parser.add_argument(
        "--firewall-mode",
        choices=["ids", "ips"],
        default=None,
        help="'ids' blocks on INPUT chain (default), 'ips' blocks on FORWARD chain (prevents traffic reaching endpoint).",
    )

    return parser


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def load_ground_truth(path: Path) -> dict[str, bool]:
    """Read a CSV with columns ip,is_malicious and return {ip: bool}.

    Returns an empty dict and logs a warning if the file is not found.
    """
    try:
        result: dict[str, bool] = {}
        with path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                ip = row["ip"].strip()
                result[ip] = bool(int(row["is_malicious"]))
        logger.info("Loaded ground truth for %d IPs from %s", len(result), path)
        return result
    except FileNotFoundError:
        logger.warning("Ground-truth file not found: %s — accuracy metrics will be skipped.", path)
        return {}


def confirm_live_mode(config: Config) -> bool:
    """Print current thresholds and prompt the user to confirm live blocking.

    Returns True only if the user types exactly "YES".
    """
    print()
    print("=" * 52)
    print("  WARNING: LIVE BLOCKING MODE REQUESTED")
    print("=" * 52)
    print(f"  fail_threshold  : {config.fail_threshold} failed logins")
    print(f"  window_seconds  : {config.window_seconds}s")
    print(f"  abuse_score_threshold: {config.abuse_score_threshold}/100")
    print(f"  firewall_host   : {config.firewall_host or '(local iptables)'}")
    print()
    print("  Real iptables DROP rules will be added.")
    print("  This affects live network traffic.")
    print("=" * 52)
    answer = input("Type YES to proceed with live blocking: ").strip()
    return answer == "YES"


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run(config: Config, args: argparse.Namespace) -> int:
    """Execute the full detection/response pipeline.

    Returns 0 on success, 1 on unrecoverable error.
    """
    # ------------------------------------------------------------------
    # 1. Initialise components
    # ------------------------------------------------------------------
    detector = SlidingWindowDetector(
        threshold=config.fail_threshold,
        window_seconds=config.window_seconds,
    )
    api_client = create_multi_intel(config)
    engine = DecisionEngine(config=config, api_client=api_client)
    firewall = FirewallController(config=config)
    reporter = Reporter(report_path=config.report_file)
    db = ThreatDatabase(config.db_path)
    notifier = EmailNotifier(config)

    # Restore previously blocked IPs from database (survives restarts)
    for ip in db.get_active_blocked_ips():
        firewall._blocked_ips.add(ip)
    if firewall._blocked_ips:
        logger.info("Restored %d blocked IPs from database", len(firewall._blocked_ips))

    # ------------------------------------------------------------------
    # 2. Log startup banner
    # ------------------------------------------------------------------
    mode_label = "WATCH (tail)" if args.watch else "BATCH"
    dry_run_label = "DRY-RUN (no real firewall changes)" if config.dry_run else "LIVE (real firewall changes)"
    if config.use_mock_api:
        api_label = f"Mock clients ({api_client.source_count} sources, no HTTP)"
    else:
        sources = ["AbuseIPDB"]
        if config.virustotal_api_key:
            sources.append("VirusTotal")
        if config.alienvault_api_key:
            sources.append("AlienVault OTX")
        api_label = " + ".join(sources)
    source_label = "FIREWALL kern.log (IPS)" if config.log_source == "firewall" else "AUTH auth.log (IDS)"
    fw_mode_label = (
        "IPS (FORWARD chain — blocks before reaching endpoint)"
        if config.firewall_mode == "ips"
        else "IDS (INPUT chain — blocks at firewall only)"
    )

    logger.info("=" * 60)
    logger.info("Automated Threat Detection System — starting up")
    logger.info("  Log file      : %s", config.log_file)
    logger.info("  Log source    : %s", source_label)
    logger.info("  Firewall mode : %s", fw_mode_label)
    logger.info("  Mode          : %s", mode_label)
    logger.info("  Dry-run       : %s", dry_run_label)
    logger.info("  API client    : %s", api_label)
    logger.info("  Threshold     : %d fails in %ds", config.fail_threshold, config.window_seconds)
    logger.info("  Database      : %s", config.db_path)
    logger.info("  Email         : %s", "enabled" if config.email_enabled else "disabled")
    logger.info("  Report        : %s", config.report_file)
    logger.info("=" * 60)

    # ------------------------------------------------------------------
    # 3. Choose log source
    # ------------------------------------------------------------------
    log_path = config.log_file

    def _process_entries(entries) -> None:
        """Inner loop: feed entries through detector → engine → firewall → reporter."""
        for entry in entries:
            db.insert_event(entry)

            detection_event = detector.process_event(entry)
            if detection_event is None:
                continue

            db.insert_detection(detection_event)
            assessment = engine.evaluate(detection_event)
            ip = assessment.ip_address

            geo = assessment.geo
            country_label = geo.country if geo and geo.country else "Unknown"
            city_label = geo.city if geo and geo.city else "?"
            asn_label = geo.asn if geo and geo.asn else "?"
            isp_label = geo.isp if geo and geo.isp else "?"
            ctx_line = (
                f"          Session: {assessment.session_id} | "
                f"Country: {country_label} | City: {city_label} | "
                f"ASN: {asn_label} | ISP: {isp_label}"
            )

            if assessment.decision == Decision.BLOCK:
                firewall_action = firewall.block_ip(ip)
                action_status = "blocked" if firewall_action.success else "block-FAILED"
                logger.info(
                    "[BLOCK] %s — score:%d  fails:%d  session:%s  country:%s  asn:%s  %s",
                    ip,
                    assessment.reputation.abuse_confidence_score,
                    detection_event.fail_count,
                    assessment.session_id,
                    country_label,
                    asn_label,
                    action_status,
                )
                print(
                    f"[BLOCK]   {ip:<18} — "
                    f"score:{assessment.reputation.abuse_confidence_score:<4} "
                    f"fails:{detection_event.fail_count}"
                )
                print(ctx_line)

            elif assessment.decision == Decision.MONITOR:
                logger.warning(
                    "[MONITOR] %s — score:%d  fails:%d  session:%s  country:%s  reason: %s",
                    ip,
                    assessment.reputation.abuse_confidence_score,
                    detection_event.fail_count,
                    assessment.session_id,
                    country_label,
                    assessment.reason,
                )
                print(
                    f"[MONITOR] {ip:<18} — "
                    f"score:{assessment.reputation.abuse_confidence_score:<4} "
                    f"fails:{detection_event.fail_count}"
                )
                print(ctx_line)

            else:  # IGNORE
                logger.debug(
                    "[IGNORE]  %s — score:%d  fails:%d  session:%s",
                    ip,
                    assessment.reputation.abuse_confidence_score,
                    detection_event.fail_count,
                    assessment.session_id,
                )
                print(
                    f"[IGNORE]  {ip:<18} — "
                    f"score:{assessment.reputation.abuse_confidence_score:<4} "
                    f"fails:{detection_event.fail_count}"
                )
                print(ctx_line)

            reporter.record(assessment)
            db.insert_assessment(assessment)
            if assessment.decision == Decision.BLOCK:
                db.add_blocked_ip(ip)
                notifier.notify_block(assessment)

    # ------------------------------------------------------------------
    # 4. Run the loop
    # ------------------------------------------------------------------
    ground_truth: dict[str, bool] | None = None

    try:  # noqa: SIM105 — outer try wraps pipeline + reporting; finally closes DB
        if args.watch:
            logger.info("Entering watch mode — press Ctrl+C to stop and print summary.")
            _process_entries(tail_log_file(log_path, poll_interval=config.poll_interval, log_source=config.log_source))
        else:
            _process_entries(parse_log_file(log_path, log_source=config.log_source))

    except FileNotFoundError as exc:
        logger.error("Log file not found: %s", exc)
        return 1

    except KeyboardInterrupt:
        print("\nInterrupted — computing summary…")
        logger.info("KeyboardInterrupt received — finalising.")

    # ------------------------------------------------------------------
    # 5. Post-loop reporting
    # ------------------------------------------------------------------
    if args.ground_truth:
        ground_truth = load_ground_truth(Path(args.ground_truth))

    # Compute cache hit/miss counts.
    # The real AbuseIPDBClient does not expose a separate miss counter, so we
    # derive it: total assessments - cache hits gives a reasonable proxy.
    cache_hits = api_client.cache_size
    # cache_misses = total unique IPs evaluated minus those served from cache.
    # We use total assessments as a conservative upper bound for misses when
    # exact tracking is unavailable.
    total_assessed = len(reporter._assessments)
    cache_misses = max(0, total_assessed - cache_hits)

    metrics = reporter.compute_metrics(
        ground_truth=ground_truth if ground_truth else None,
        api_cache_hits=cache_hits,
        api_cache_misses=cache_misses,
    )
    reporter.write_csv()
    reporter.print_summary(metrics)

    db.close()
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Parse arguments, configure logging, load config, and launch the pipeline."""
    parser = build_parser()
    args = parser.parse_args()

    # Logging must be set up before any logger usage.
    setup_logging(args.log_level)

    try:
        # Load config from file (or defaults if no --config given).
        config = load_config(args.config)

        # ----------------------------------------------------------------
        # Apply CLI overrides to config
        # ----------------------------------------------------------------
        if args.log_file is not None:
            config.log_file = Path(args.log_file)

        if args.report_file is not None:
            config.report_file = Path(args.report_file)

        if args.no_api:
            config.use_mock_api = True

        if args.firewall_host is not None:
            config.firewall_host = args.firewall_host

        if args.threshold is not None:
            config.fail_threshold = args.threshold

        if args.window is not None:
            config.window_seconds = args.window

        if args.log_source is not None:
            config.log_source = args.log_source

        if args.firewall_mode is not None:
            config.firewall_mode = args.firewall_mode

        # Dry-run / live resolution:
        #   --dry-run   → force dry_run = True
        #   --live      → request dry_run = False (requires confirmation)
        #   neither     → use value from config (defaults to True)
        if args.dry_run:
            config.dry_run = True
        elif args.live:
            if not confirm_live_mode(config):
                print("Live mode not confirmed — aborting.")
                sys.exit(1)
            config.dry_run = False

        # ----------------------------------------------------------------
        # Run pipeline
        # ----------------------------------------------------------------
        return_code = run(config, args)
        sys.exit(return_code)

    except KeyboardInterrupt:
        logger.info("Aborted by user.")
        sys.exit(0)

    except Exception as exc:  # noqa: BLE001
        logger.exception("Fatal error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
