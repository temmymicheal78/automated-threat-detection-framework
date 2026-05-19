from dataclasses import dataclass, field
from pathlib import Path
import os
import json
import yaml
from dotenv import load_dotenv


@dataclass
class Config:
    # Detection thresholds
    fail_threshold: int = 5
    window_seconds: int = 300
    abuse_score_threshold: int = 50
    max_age_days: int = 90
    # API
    api_key: str = ""
    api_base_url: str = "https://api.abuseipdb.com/api/v2"
    # Firewall
    dry_run: bool = True
    firewall_host: str = ""
    firewall_user: str = "root"
    firewall_ssh_key: str = ""
    # Paths
    log_file: Path = field(default_factory=lambda: Path("data/sample_logs/auth.log"))
    report_file: Path = field(default_factory=lambda: Path("data/results/report.csv"))
    # Runtime
    poll_interval: float = 0.5
    api_rate_limit_per_minute: int = 60
    use_mock_api: bool = False
    # Database
    db_path: str = "data/threat_detector.db"
    # Email notifications
    email_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    alert_email_to: str = ""
    alert_email_from: str = ""
    # Log source: "auth" (default, reads auth.log) or "firewall" (reads kern.log / iptables LOG)
    log_source: str = "auth"
    # Firewall mode: "ids" blocks on INPUT chain (protects firewall only),
    # "ips" blocks on FORWARD chain (prevents traffic from reaching the endpoint)
    firewall_mode: str = "ids"
    # Additional threat intel API keys (optional — leave empty to skip)
    virustotal_api_key: str = ""
    alienvault_api_key: str = ""


def load_config(config_path: str | None = None) -> Config:
    """Load configuration from optional file, then override with environment variables."""
    load_dotenv()

    config_dict: dict = {}

    if config_path is not None:
        path = Path(config_path)
        with open(path, "r", encoding="utf-8") as fh:
            if path.suffix == ".json":
                config_dict = json.load(fh)
            elif path.suffix in (".yaml", ".yml"):
                config_dict = yaml.safe_load(fh) or {}
            else:
                raise ValueError(f"Unsupported config file format: {path.suffix}")

    # Build Config from file values (only pass keys that exist in the dataclass)
    valid_fields = Config.__dataclass_fields__.keys()
    filtered = {k: v for k, v in config_dict.items() if k in valid_fields}
    cfg = Config(**filtered)

    # Override with environment variables
    api_key = os.environ.get("ABUSE_IPDB_KEY")
    if api_key is not None:
        cfg.api_key = api_key

    fail_threshold = os.environ.get("FAIL_THRESHOLD")
    if fail_threshold is not None:
        cfg.fail_threshold = int(fail_threshold)

    window_seconds = os.environ.get("WINDOW_SECONDS")
    if window_seconds is not None:
        cfg.window_seconds = int(window_seconds)

    abuse_score_threshold = os.environ.get("ABUSE_SCORE_THRESHOLD")
    if abuse_score_threshold is not None:
        cfg.abuse_score_threshold = int(abuse_score_threshold)

    dry_run = os.environ.get("DRY_RUN")
    if dry_run is not None:
        cfg.dry_run = dry_run.lower() not in ("false", "0", "no")

    firewall_host = os.environ.get("FIREWALL_HOST")
    if firewall_host is not None:
        cfg.firewall_host = firewall_host

    firewall_user = os.environ.get("FIREWALL_USER")
    if firewall_user is not None:
        cfg.firewall_user = firewall_user

    log_file = os.environ.get("LOG_FILE")
    if log_file is not None:
        cfg.log_file = Path(log_file)

    report_file = os.environ.get("REPORT_FILE")
    if report_file is not None:
        cfg.report_file = Path(report_file)

    use_mock_api = os.environ.get("USE_MOCK_API")
    if use_mock_api is not None:
        cfg.use_mock_api = use_mock_api.lower() not in ("false", "0", "no")

    db_path = os.environ.get("DB_PATH")
    if db_path is not None:
        cfg.db_path = db_path

    email_enabled = os.environ.get("EMAIL_ENABLED")
    if email_enabled is not None:
        cfg.email_enabled = email_enabled.lower() not in ("false", "0", "no")

    smtp_host = os.environ.get("SMTP_HOST")
    if smtp_host is not None:
        cfg.smtp_host = smtp_host

    smtp_port = os.environ.get("SMTP_PORT")
    if smtp_port is not None:
        cfg.smtp_port = int(smtp_port)

    smtp_user = os.environ.get("SMTP_USER")
    if smtp_user is not None:
        cfg.smtp_user = smtp_user

    smtp_password = os.environ.get("SMTP_PASSWORD")
    if smtp_password is not None:
        cfg.smtp_password = smtp_password

    alert_email_to = os.environ.get("ALERT_EMAIL_TO")
    if alert_email_to is not None:
        cfg.alert_email_to = alert_email_to

    alert_email_from = os.environ.get("ALERT_EMAIL_FROM")
    if alert_email_from is not None:
        cfg.alert_email_from = alert_email_from

    log_source = os.environ.get("LOG_SOURCE")
    if log_source is not None:
        cfg.log_source = log_source

    firewall_mode = os.environ.get("FIREWALL_MODE")
    if firewall_mode is not None:
        cfg.firewall_mode = firewall_mode

    vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if vt_key is not None:
        cfg.virustotal_api_key = vt_key

    otx_key = os.environ.get("ALIENVAULT_API_KEY")
    if otx_key is not None:
        cfg.alienvault_api_key = otx_key

    # Ensure Path types
    cfg.log_file = Path(cfg.log_file)
    cfg.report_file = Path(cfg.report_file)

    return cfg
