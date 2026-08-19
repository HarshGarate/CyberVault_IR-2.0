from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = DATA_DIR / "incident_reports"
EVIDENCE_DIR = DATA_DIR / "evidence"
LOGS_DIR = DATA_DIR / "logs"

DATABASE_FILE = DATA_DIR / "cybervault.db"
ACTIVITY_LOG = LOGS_DIR / "activity_log.txt"
SECURITY_LOG = LOGS_DIR / "security_log.txt"

MAX_LOGIN_ATTEMPTS = 3

ROLES = ("analyst", "manager", "admin")
SEVERITIES = ("Low", "Medium", "High", "Critical")
STATUSES = ("Open", "Investigating", "Contained", "Resolved", "Closed")
INCIDENT_TYPES = (
    "Phishing",
    "Malware",
    "Unauthorized Access",
    "Data Leakage",
    "Suspicious Network Activity",
    "Other",
)


def create_project_folders():
    for folder in (DATA_DIR, REPORTS_DIR, EVIDENCE_DIR, LOGS_DIR):
        folder.mkdir(parents=True, exist_ok=True)
