from datetime import datetime
from pathlib import Path
import shutil
import uuid

from config import BASE_DIR, REPORTS_DIR, EVIDENCE_DIR
from database import (
    add_incident,
    add_evidence,
    update_incident_hash,
    update_incident_status_and_hash,
)
from security import hash_file, log_activity


# FIND THE CORRECT REPORT FILE


def resolve_report_path(report_path):
    """
    Finds the report even when the project folder was moved.

    It first checks the path stored in the database.
    If that path is old, it searches the current
    incident_reports folder using the report filename.
    """

    stored_path = Path(str(report_path))

    # If the database contains a relative path,
    # join it with the current project folder.
    if not stored_path.is_absolute():
        stored_path = BASE_DIR / stored_path

    # Use the stored path when it is still correct.
    if stored_path.exists():
        return stored_path

    # The old absolute path may no longer work after
    # moving or renaming the project folder.
    report_filename = Path(str(report_path)).name

    # Search all user folders for the same incident file.
    matching_files = list(
        REPORTS_DIR.rglob(report_filename)
    )

    if len(matching_files) == 1:
        return matching_files[0]

    if len(matching_files) > 1:
        raise FileNotFoundError(
            "More than one report file has the same name.\n\n"
            f"Filename: {report_filename}"
        )

    raise FileNotFoundError(
        "The incident report could not be found.\n\n"
        f"Stored database path:\n{report_path}\n\n"
        f"Current reports folder:\n{REPORTS_DIR}"
    )


# GENERATE INCIDENT CODE

def generate_incident_code():
    """
    Generates a unique incident code.

    Example:
    INC-20260805-A12BC
    """

    date_part = datetime.now().strftime("%Y%m%d")
    random_part = uuid.uuid4().hex[:5].upper()

    return f"INC-{date_part}-{random_part}"


# CREATE AND WRITE INCIDENT REPORT


def create_incident_report(
    title,
    incident_type,
    severity,
    description,
    indicators,
    owner_username,
    created_by,
):
    """
    Creates a new incident-report text file.

    File mode:
    x = create a new file

    The initial incident information is written
    using file.write().
    """

    incident_code = generate_incident_code()

    # Create a folder for the incident owner.
    owner_folder = REPORTS_DIR / owner_username

    owner_folder.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Create the report filename.
    report_path = owner_folder / f"{incident_code}.txt"

    created_at = datetime.now().strftime(
        "%d-%m-%Y %H:%M:%S"
    )

    report_text = (
        "CYBERVAULT INCIDENT REPORT\n"
        + "=" * 55
        + "\n"
        + f"Incident ID   : {incident_code}\n"
        + f"Title         : {title.strip()}\n"
        + f"Type          : {incident_type}\n"
        + f"Severity      : {severity}\n"
        + "Status        : Open\n"
        + f"Owner         : {owner_username}\n"
        + f"Created By    : {created_by}\n"
        + f"Created At    : {created_at}\n"
        + "=" * 55
        + "\n\n"
        + "DESCRIPTION\n"
        + "-" * 55
        + "\n"
        + description.strip()
        + "\n\n"
        + "INDICATORS OF COMPROMISE\n"
        + "-" * 55
        + "\n"
        + (indicators.strip() or "None provided")
        + "\n\n"
        + "INVESTIGATION UPDATES\n"
        + "-" * 55
        + "\n"
    )

    # "x" creates a new file and prevents overwrite.
    with open(
        report_path,
        "x",
        encoding="utf-8",
    ) as file:
        file.write(report_text)

    # Calculate the first trusted file hash.
    stored_hash = hash_file(report_path)

    # Store a relative path instead of a full absolute path.
    # This prevents problems when the project is moved.
    relative_report_path = report_path.relative_to(
        BASE_DIR
    )

    add_incident(
        incident_code=incident_code,
        title=title.strip(),
        incident_type=incident_type,
        severity=severity,
        status="Open",
        owner_username=owner_username,
        created_by=created_by,
        report_path=str(relative_report_path),
        stored_hash=stored_hash,
    )

    log_activity(
        f"{created_by} CREATED and WROTE "
        f"incident {incident_code}"
    )

    return incident_code



# READ INCIDENT REPORT

def read_incident_report(report_path):
    """
    Reads and returns the complete incident report.

    File mode:
    r = read
    """

    correct_path = resolve_report_path(report_path)

    with open(
        correct_path,
        "r",
        encoding="utf-8",
    ) as file:
        return file.read()


# APPEND INVESTIGATION UPDATE

def append_incident_update(
    incident_code,
    report_path,
    update_text,
    status,
    updated_by,
):
    """
    Adds a new investigation update without deleting
    the previous report information.

    File mode:
    a = append
    """

    correct_path = resolve_report_path(report_path)

    timestamp = datetime.now().strftime(
        "%d-%m-%Y %H:%M:%S"
    )

    update_block = (
        "\n"
        + f"[{timestamp}] Update by {updated_by}\n"
        + f"Status: {status}\n"
        + "-" * 55
        + "\n"
        + update_text.strip()
        + "\n"
    )

    with open(
        correct_path,
        "a",
        encoding="utf-8",
    ) as file:
        file.write(update_block)

    # An authorized update changes the file,
    # so calculate and save the new trusted hash.
    new_hash = hash_file(correct_path)

    update_incident_status_and_hash(
        incident_code,
        status,
        new_hash,
    )

    log_activity(
        f"{updated_by} APPENDED update to "
        f"incident {incident_code}"
    )


# VERIFY INCIDENT INTEGRITY

def verify_incident_integrity(
    report_path,
    stored_hash,
):
    """
    Compares the current SHA-256 hash with
    the trusted hash stored in SQLite.
    """

    correct_path = resolve_report_path(report_path)

    current_hash = hash_file(correct_path)

    hashes_match = current_hash == stored_hash

    return hashes_match, current_hash


# ACCEPT CURRENT REPORT HASH

def accept_new_integrity_hash(
    incident_code,
    report_path,
    accepted_by,
):
    """
    Saves the current report hash as the new trusted hash.

    This should only be used by a Manager or Administrator
    after reviewing the modified report.
    """

    correct_path = resolve_report_path(report_path)

    new_hash = hash_file(correct_path)

    update_incident_hash(
        incident_code,
        new_hash,
    )

    log_activity(
        f"{accepted_by} ACCEPTED new integrity hash "
        f"for {incident_code}"
    )

    return new_hash


# ATTACH EVIDENCE

def attach_evidence(
    incident_code,
    source_path,
    uploaded_by,
):
    """
    Copies an evidence file into the project's
    evidence folder and calculates its SHA-256 hash.
    """

    source = Path(source_path)

    if not source.is_file():
        raise FileNotFoundError(
            "The selected evidence file does not exist."
        )

    # Create a separate evidence folder for the incident.
    incident_folder = EVIDENCE_DIR / incident_code

    incident_folder.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Replace spaces and add a random prefix
    # to avoid duplicate filenames.
    safe_name = source.name.replace(" ", "_")

    stored_filename = (
        f"{uuid.uuid4().hex[:8]}_{safe_name}"
    )

    destination = incident_folder / stored_filename

    # Copy the evidence file.
    shutil.copy2(
        source,
        destination,
    )

    # Calculate its SHA-256 fingerprint.
    evidence_hash = hash_file(destination)

    # Store a relative evidence path in the database.
    relative_evidence_path = destination.relative_to(
        BASE_DIR
    )

    add_evidence(
        incident_code=incident_code,
        original_name=source.name,
        stored_path=str(relative_evidence_path),
        sha256=evidence_hash,
        uploaded_by=uploaded_by,
    )

    log_activity(
        f"{uploaded_by} ATTACHED evidence to "
        f"incident {incident_code}: {source.name}"
    )

    return destination, evidence_hash