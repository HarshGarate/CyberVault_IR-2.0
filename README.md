# CyberVault IR

CyberVault IR is a beginner-friendly Python desktop project that demonstrates how file handling is used in a realistic cybersecurity incident-response workflow.

The project uses only Python's standard library, keeps the modules understandable, and still demonstrates strong interview topics.

## Main features

- One-time administrator setup
- One common login screen for all roles
- SOC Analyst, Incident Manager and Administrator permissions
- SQLite user and incident database
- PBKDF2-SHA256 password hashing
- Temporary-password change on first login
- Incident creation, writing, reading and appending
- SHA-256 report integrity verification
- Evidence attachment and hashing
- Activity and security logs
- Administrator user management
- Account enabling, disabling and password reset

## File handling demonstrated

The project intentionally uses all required file modes:

```python
open(path, "x")  # Create a new incident report
open(path, "w")  # Write logs and report contents
open(path, "r")  # Read reports and logs
open(path, "a")  # Append investigation updates and audit records
```

## Files you create manually

These files are already included:

```text
CyberVault_IR/
├── main.py
├── config.py
├── database.py
├── security.py
├── incident_manager.py
├── gui.py
├── run_windows.bat
└── README.md
```

The following are created automatically:

```text
data/
├── cybervault.db
├── incident_reports/
├── evidence/
└── logs/
    ├── activity_log.txt
    └── security_log.txt
```

## Windows installation

### 1. Install Python

Install Python 3.10 or newer and enable:

```text
Add Python to PATH
```

### 2. Extract the ZIP

Extract the project and open the folder in VS Code.

### 3. Check Python

Open the VS Code terminal:

```powershell
py --version
```

### 4. Check Tkinter

```powershell
py -m tkinter
```

A small test window should appear.

### 5. Start the project

```powershell
py main.py
```

You may also double-click:

```text
run_windows.bat
```

No `pip install` command is needed.

## First launch

The application shows a one-time setup screen.

Create your first administrator:

```text
Full name: Harsh Garate
Username: HarshG
Password: GarateH123@
Confirm password: GarateH123@
```

The password must contain:

- At least 8 characters
- One uppercase letter
- One lowercase letter
- One number

After setup, log in using the same account.

## Create presentation accounts

Open:

```text
User Management → Create User
```

Create an Analyst:

```text
Full name: SOC Analyst
Username: analyst1
Temporary password: Cyber123
Role: analyst
```

Create a Manager:

```text
Full name: Incident Manager
Username: manager1
Temporary password: Cyber123
Role: manager
```

The user must change the temporary password at first login.

## Roles

### SOC Analyst

- Creates incidents
- Reads assigned incidents
- Appends investigation updates
- Attaches evidence
- Verifies file integrity
- Cannot view all users or system logs

### Incident Manager

- Views all incidents
- Reads and updates any incident
- Reviews activity and security logs
- Accepts a new integrity baseline after investigation

### Administrator

- Has manager permissions
- Creates Analyst and Manager accounts
- Enables and disables users
- Resets passwords

## Demonstration workflow

1. Log in as an Analyst.
2. Create a phishing incident.
3. Read the generated report.
4. Append an investigation update.
5. Attach an evidence file.
6. Verify integrity.
7. Edit the report manually in Notepad.
8. Verify integrity again to show the warning.
9. Log in as Manager and accept the new hash after review.
10. Log in as Administrator and demonstrate user management.

## Reset the project

Close the application and delete the `data` folder.

Run:

```powershell
py main.py
```

The project will return to its first-run state.
