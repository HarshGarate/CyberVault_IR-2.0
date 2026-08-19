import sqlite3
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from config import (
    ACTIVITY_LOG,
    INCIDENT_TYPES,
    MAX_LOGIN_ATTEMPTS,
    SECURITY_LOG,
    SEVERITIES,
    STATUSES,
)
from database import (
    authenticate_user,
    change_password,
    create_user,
    get_incident,
    list_evidence,
    list_incidents,
    list_users,
    reset_user_password,
    set_user_active,
    user_count,
)
from incident_manager import (
    accept_new_integrity_hash,
    append_incident_update,
    attach_evidence,
    create_incident_report,
    read_incident_report,
    verify_incident_integrity,
)
from security import log_activity, log_security, read_log


class CyberVaultApp:
    def __init__(self, root):
        self.root = root
        self.current_user = None
        self.login_attempts = MAX_LOGIN_ATTEMPTS

        self.root.title("CyberVault - Student Incident Response System")
        self.root.minsize(1000, 650)
        self.root.resizable(True, True)

        try:
            self.root.state("zoomed")
        except tk.TclError:
            self.root.geometry("1200x750")

        self.root.protocol("WM_DELETE_WINDOW", self.close_application)

        self.setup_style()

        if user_count() == 0:
            self.show_first_setup()
        else:
            self.show_login()

    def setup_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("Title.TLabel", font=("Segoe UI", 22, "bold"))
        style.configure("Heading.TLabel", font=("Segoe UI", 14, "bold"))
        style.configure("TButton", font=("Segoe UI", 10), padding=7)
        style.configure("Treeview", rowheight=28, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def close_application(self):
        if messagebox.askyesno("Exit", "Close CyberVault?"):
            self.root.destroy()

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def build_center_card(self, title, subtitle):
        outer = ttk.Frame(self.root, padding=20)
        outer.pack(fill="both", expand=True)

        card = ttk.LabelFrame(outer, padding=35)
        card.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(card, text=title, style="Title.TLabel").grid(
            row=0, column=0, columnspan=2, pady=(0, 5)
        )
        ttk.Label(card, text=subtitle).grid(
            row=1, column=0, columnspan=2, pady=(0, 25)
        )

        return card

    # ---------------- FIRST SETUP ----------------

    def show_first_setup(self):
        self.clear_window()
        self.root.title("First Setup - CyberVault")

        card = self.build_center_card(
            "CyberVault First Setup",
            "Create the first System Administrator account",
        )

        fields = [
            ("Full name", False),
            ("Username", False),
            ("Password", True),
            ("Confirm password", True),
        ]

        self.setup_entries = []

        for index, (label, password_field) in enumerate(fields, start=2):
            ttk.Label(card, text=label).grid(
                row=index, column=0, sticky="w", padx=(0, 12), pady=8
            )

            entry = ttk.Entry(
                card,
                width=35,
                show="*" if password_field else "",
            )
            entry.grid(row=index, column=1, pady=8)
            self.setup_entries.append(entry)

        ttk.Button(
            card,
            text="Complete Setup",
            command=self.complete_first_setup,
        ).grid(
            row=6,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(20, 0),
        )

    def complete_first_setup(self):
        full_name, username, password, confirm = [
            entry.get() for entry in self.setup_entries
        ]

        error = self.validate_account_data(
            full_name,
            username,
            password,
            confirm,
        )

        if error:
            messagebox.showerror("Setup Error", error)
            return

        try:
            create_user(
                username=username,
                full_name=full_name,
                password=password,
                role="admin",
            )
        except sqlite3.IntegrityError:
            messagebox.showerror("Setup Error", "Username already exists.")
            return

        log_security(f"FIRST ADMIN CREATED: {username.lower()}")
        messagebox.showinfo("Setup Complete", "Administrator created successfully.")
        self.show_login()

    # ---------------- LOGIN ----------------

    def show_login(self):
        self.clear_window()
        self.current_user = None
        self.login_attempts = MAX_LOGIN_ATTEMPTS
        self.root.title("Login - CyberVault")

        card = self.build_center_card(
            "CyberVault IR",
            "Incident Response and Audit Management",
        )

        ttk.Label(card, text="Username").grid(
            row=2, column=0, sticky="w", padx=(0, 12), pady=8
        )
        self.login_username = ttk.Entry(card, width=35)
        self.login_username.grid(row=2, column=1, pady=8)

        ttk.Label(card, text="Password").grid(
            row=3, column=0, sticky="w", padx=(0, 12), pady=8
        )
        self.login_password = ttk.Entry(card, width=35, show="*")
        self.login_password.grid(row=3, column=1, pady=8)

        self.show_password_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            card,
            text="Show password",
            variable=self.show_password_var,
            command=self.toggle_login_password,
        ).grid(row=4, column=1, sticky="w")

        self.login_button = ttk.Button(
            card,
            text="Sign In",
            command=self.handle_login,
        )
        self.login_button.grid(
            row=5,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(18, 8),
        )

        self.attempts_label = ttk.Label(
            card,
            text=f"Attempts remaining: {self.login_attempts}",
        )
        self.attempts_label.grid(row=6, column=0, columnspan=2)

        self.login_password.bind("<Return>", lambda event: self.handle_login())
        self.login_username.focus_set()

    def toggle_login_password(self):
        self.login_password.config(
            show="" if self.show_password_var.get() else "*"
        )

    def handle_login(self):
        username = self.login_username.get().strip()
        password = self.login_password.get()

        if not username or not password:
            messagebox.showwarning(
                "Missing Information",
                "Enter username and password.",
            )
            return

        user = authenticate_user(username, password)

        if user:
            self.current_user = user
            log_security(
                f"LOGIN SUCCESS: {user['username']} ({user['role']})"
            )

            if user["must_change_password"]:
                self.force_password_change()
            else:
                self.show_dashboard()

            return

        self.login_attempts -= 1
        self.login_password.delete(0, tk.END)

        log_security(f"LOGIN FAILED: {username.lower()}")

        self.attempts_label.config(
            text=f"Attempts remaining: {self.login_attempts}"
        )

        if self.login_attempts <= 0:
            self.login_button.config(state="disabled")
            messagebox.showerror(
                "Login Locked",
                "Too many failed attempts. Restart the application.",
            )
        else:
            messagebox.showerror(
                "Login Failed",
                "Incorrect username, password, or disabled account.",
            )

    def force_password_change(self):
        new_password = simpledialog.askstring(
            "Password Change Required",
            "Enter a new password:",
            show="*",
            parent=self.root,
        )

        if new_password is None:
            self.current_user = None
            self.show_login()
            return

        if not self.password_is_valid(new_password):
            messagebox.showerror(
                "Weak Password",
                "Use at least 8 characters with uppercase, lowercase and a number.",
            )
            self.force_password_change()
            return

        change_password(self.current_user["id"], new_password)
        self.current_user["must_change_password"] = 0

        log_security(
            f"PASSWORD CHANGED: {self.current_user['username']}"
        )

        messagebox.showinfo("Success", "Password changed successfully.")
        self.show_dashboard()

    # ---------------- DASHBOARD ----------------

    def show_dashboard(self):
        self.clear_window()
        self.root.title("CyberVault Dashboard")

        header = ttk.Frame(self.root, padding=15)
        header.pack(fill="x")

        ttk.Label(
            header,
            text="CyberVault Incident Response System",
            style="Title.TLabel",
        ).pack(side="left")

        ttk.Label(
            header,
            text=(
                f"{self.current_user['full_name']} | "
                f"{self.current_user['role'].title()}"
            ),
        ).pack(side="right", padx=(10, 0))

        ttk.Button(
            header,
            text="Logout",
            command=self.logout,
        ).pack(side="right")

        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        incident_tab = ttk.Frame(notebook, padding=12)
        create_tab = ttk.Frame(notebook, padding=12)

        notebook.add(incident_tab, text="Incidents")
        notebook.add(create_tab, text="Create Incident")

        self.build_incident_tab(incident_tab)
        self.build_create_incident_tab(create_tab)

        if self.current_user["role"] in ("manager", "admin"):
            logs_tab = ttk.Frame(notebook, padding=12)
            notebook.add(logs_tab, text="Audit Logs")
            self.build_logs_tab(logs_tab)

        if self.current_user["role"] == "admin":
            users_tab = ttk.Frame(notebook, padding=12)
            notebook.add(users_tab, text="User Management")
            self.build_users_tab(users_tab)

        self.status_bar = ttk.Label(
            self.root,
            text="Ready",
            relief="sunken",
            anchor="w",
            padding=6,
        )
        self.status_bar.pack(fill="x", side="bottom")

    # ---------------- INCIDENT LIST ----------------

    def build_incident_tab(self, parent):
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill="x", pady=(0, 10))

        ttk.Label(
            toolbar,
            text="Incident Records",
            style="Heading.TLabel",
        ).pack(side="left")

        ttk.Button(
            toolbar,
            text="Refresh",
            command=self.refresh_incident_table,
        ).pack(side="right")

        columns = (
            "code",
            "title",
            "severity",
            "status",
            "owner",
            "created",
        )

        self.incident_tree = ttk.Treeview(
            parent,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        headings = {
            "code": "Incident ID",
            "title": "Title",
            "severity": "Severity",
            "status": "Status",
            "owner": "Owner",
            "created": "Created",
        }

        widths = {
            "code": 170,
            "title": 260,
            "severity": 90,
            "status": 110,
            "owner": 110,
            "created": 150,
        }

        for column in columns:
            self.incident_tree.heading(column, text=headings[column])
            self.incident_tree.column(
                column,
                width=widths[column],
                anchor="w",
            )

        self.incident_tree.pack(fill="both", expand=True)

        action_frame = ttk.Frame(parent)
        action_frame.pack(fill="x", pady=(10, 0))

        ttk.Button(
            action_frame,
            text="Read Report",
            command=self.read_selected_incident,
        ).pack(side="left", padx=(0, 6))

        ttk.Button(
            action_frame,
            text="Append Update",
            command=self.open_append_window,
        ).pack(side="left", padx=6)

        ttk.Button(
            action_frame,
            text="Verify Integrity",
            command=self.verify_selected_incident,
        ).pack(side="left", padx=6)

        ttk.Button(
            action_frame,
            text="Attach Evidence",
            command=self.attach_selected_evidence,
        ).pack(side="left", padx=6)

        ttk.Button(
            action_frame,
            text="View Evidence",
            command=self.view_selected_evidence,
        ).pack(side="left", padx=6)

        if self.current_user["role"] in ("manager", "admin"):
            ttk.Button(
                action_frame,
                text="Accept Current Hash",
                command=self.accept_selected_hash,
            ).pack(side="left", padx=6)

        self.refresh_incident_table()

    def refresh_incident_table(self):
        for item in self.incident_tree.get_children():
            self.incident_tree.delete(item)

        incidents = list_incidents(
            self.current_user["username"],
            self.current_user["role"],
        )

        for incident in incidents:
            self.incident_tree.insert(
                "",
                "end",
                iid=incident["incident_code"],
                values=(
                    incident["incident_code"],
                    incident["title"],
                    incident["severity"],
                    incident["status"],
                    incident["owner_username"],
                    incident["created_at"].replace("T", " "),
                ),
            )

    def selected_incident(self):
        selected = self.incident_tree.selection()

        if not selected:
            messagebox.showwarning(
                "No Incident Selected",
                "Select an incident first.",
            )
            return None

        return get_incident(selected[0])

    def read_selected_incident(self):
        incident = self.selected_incident()

        if incident is None:
            return

        try:
            content = read_incident_report(incident["report_path"])
        except Exception as error:
            messagebox.showerror("Read Error", str(error))
            return

        self.show_text_window(
            f"Report - {incident['incident_code']}",
            content,
        )

        log_activity(
            f"{self.current_user['username']} READ incident "
            f"{incident['incident_code']}"
        )

    def open_append_window(self):
        incident = self.selected_incident()

        if incident is None:
            return

        window = tk.Toplevel(self.root)
        window.title(f"Append Update - {incident['incident_code']}")
        window.geometry("650x480")
        window.transient(self.root)
        window.grab_set()

        frame = ttk.Frame(window, padding=18)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="New Status").pack(anchor="w")
        status_box = ttk.Combobox(
            frame,
            values=STATUSES,
            state="readonly",
        )
        status_box.set(incident["status"])
        status_box.pack(fill="x", pady=(4, 12))

        ttk.Label(frame, text="Investigation Update").pack(anchor="w")
        update_text = tk.Text(frame, height=16, wrap="word")
        update_text.pack(fill="both", expand=True, pady=(4, 12))

        def save_update():
            text = update_text.get("1.0", tk.END).strip()

            if not text:
                messagebox.showwarning(
                    "Missing Update",
                    "Enter investigation details.",
                    parent=window,
                )
                return

            try:
                append_incident_update(
                    incident_code=incident["incident_code"],
                    report_path=incident["report_path"],
                    update_text=text,
                    status=status_box.get(),
                    updated_by=self.current_user["username"],
                )
            except Exception as error:
                messagebox.showerror(
                    "Append Error",
                    str(error),
                    parent=window,
                )
                return

            messagebox.showinfo(
                "Saved",
                "Investigation update appended.",
                parent=window,
            )
            window.destroy()
            self.refresh_incident_table()

        ttk.Button(
            frame,
            text="Append Update",
            command=save_update,
        ).pack(fill="x")

    def verify_selected_incident(self):
        incident = self.selected_incident()

        if incident is None:
            return

        try:
            valid, current_hash = verify_incident_integrity(
                incident["report_path"],
                incident["stored_hash"],
            )
        except Exception as error:
            messagebox.showerror("Integrity Error", str(error))
            return

        if valid:
            messagebox.showinfo(
                "Integrity Verified",
                "The report has not been changed outside the application.",
            )
        else:
            log_security(
                f"INTEGRITY WARNING: {incident['incident_code']} "
                f"checked by {self.current_user['username']}"
            )

            messagebox.showwarning(
                "Integrity Warning",
                "The current SHA-256 hash does not match the stored hash.\n\n"
                f"Current hash:\n{current_hash}",
            )

    def accept_selected_hash(self):
        incident = self.selected_incident()

        if incident is None:
            return

        if not messagebox.askyesno(
            "Accept Hash",
            "Accept the current report as the new trusted version?",
        ):
            return

        try:
            new_hash = accept_new_integrity_hash(
                incident["incident_code"],
                incident["report_path"],
                self.current_user["username"],
            )
        except Exception as error:
            messagebox.showerror("Hash Error", str(error))
            return

        messagebox.showinfo(
            "Hash Updated",
            f"New SHA-256 baseline saved:\n{new_hash}",
        )

    def attach_selected_evidence(self):
        incident = self.selected_incident()

        if incident is None:
            return

        source_path = filedialog.askopenfilename(
            title="Select Evidence File",
        )

        if not source_path:
            return

        try:
            destination, file_hash = attach_evidence(
                incident["incident_code"],
                source_path,
                self.current_user["username"],
            )
        except Exception as error:
            messagebox.showerror("Evidence Error", str(error))
            return

        messagebox.showinfo(
            "Evidence Attached",
            f"Stored at:\n{destination}\n\nSHA-256:\n{file_hash}",
        )

    def view_selected_evidence(self):
        incident = self.selected_incident()

        if incident is None:
            return

        evidence_items = list_evidence(incident["incident_code"])

        if not evidence_items:
            messagebox.showinfo(
                "Evidence",
                "No evidence files are attached.",
            )
            return

        lines = []

        for item in evidence_items:
            lines.append(
                f"File: {item['original_name']}\n"
                f"Uploaded by: {item['uploaded_by']}\n"
                f"Uploaded at: {item['uploaded_at']}\n"
                f"SHA-256: {item['sha256']}\n"
                f"Stored path: {item['stored_path']}\n"
                + "-" * 70
            )

        self.show_text_window(
            f"Evidence - {incident['incident_code']}",
            "\n".join(lines),
        )

    # ---------------- CREATE INCIDENT ----------------

    def build_create_incident_tab(self, parent):
        form = ttk.LabelFrame(parent, text="New Incident", padding=18)
        form.pack(fill="both", expand=True)

        form.grid_columnconfigure(1, weight=1)
        form.grid_rowconfigure(5, weight=1)
        form.grid_rowconfigure(6, weight=1)

        ttk.Label(form, text="Title").grid(
            row=0, column=0, sticky="w", padx=(0, 12), pady=6
        )
        self.incident_title = ttk.Entry(form)
        self.incident_title.grid(
            row=0, column=1, sticky="ew", pady=6
        )

        ttk.Label(form, text="Type").grid(
            row=1, column=0, sticky="w", padx=(0, 12), pady=6
        )
        self.incident_type = ttk.Combobox(
            form,
            values=INCIDENT_TYPES,
            state="readonly",
        )
        self.incident_type.set(INCIDENT_TYPES[0])
        self.incident_type.grid(
            row=1, column=1, sticky="ew", pady=6
        )

        ttk.Label(form, text="Severity").grid(
            row=2, column=0, sticky="w", padx=(0, 12), pady=6
        )
        self.incident_severity = ttk.Combobox(
            form,
            values=SEVERITIES,
            state="readonly",
        )
        self.incident_severity.set("Medium")
        self.incident_severity.grid(
            row=2, column=1, sticky="ew", pady=6
        )

        ttk.Label(form, text="Owner").grid(
            row=3, column=0, sticky="w", padx=(0, 12), pady=6
        )
        self.incident_owner = ttk.Combobox(
            form,
            state="readonly",
        )

        if self.current_user["role"] == "analyst":
            owner_values = [self.current_user["username"]]
        else:
            owner_values = [
                user["username"]
                for user in list_users()
                if user["role"] == "analyst" and user["is_active"]
            ]

            if not owner_values:
                owner_values = [self.current_user["username"]]

        self.incident_owner["values"] = owner_values
        self.incident_owner.set(owner_values[0])
        self.incident_owner.grid(
            row=3, column=1, sticky="ew", pady=6
        )

        ttk.Label(form, text="Description").grid(
            row=4, column=0, sticky="nw", padx=(0, 12), pady=6
        )
        self.incident_description = tk.Text(form, height=8, wrap="word")
        self.incident_description.grid(
            row=4, column=1, sticky="nsew", pady=6
        )

        ttk.Label(form, text="Indicators").grid(
            row=5, column=0, sticky="nw", padx=(0, 12), pady=6
        )
        self.incident_indicators = tk.Text(form, height=6, wrap="word")
        self.incident_indicators.grid(
            row=5, column=1, sticky="nsew", pady=6
        )

        ttk.Button(
            form,
            text="Create and Write Incident Report",
            command=self.create_new_incident,
        ).grid(
            row=6,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(15, 0),
        )

    def create_new_incident(self):
        title = self.incident_title.get().strip()
        description = self.incident_description.get(
            "1.0",
            tk.END,
        ).strip()

        if not title or not description:
            messagebox.showwarning(
                "Missing Information",
                "Title and description are required.",
            )
            return

        try:
            incident_code = create_incident_report(
                title=title,
                incident_type=self.incident_type.get(),
                severity=self.incident_severity.get(),
                description=description,
                indicators=self.incident_indicators.get(
                    "1.0",
                    tk.END,
                ),
                owner_username=self.incident_owner.get(),
                created_by=self.current_user["username"],
            )
        except Exception as error:
            messagebox.showerror("Incident Error", str(error))
            return

        messagebox.showinfo(
            "Incident Created",
            f"Incident report created:\n{incident_code}",
        )

        self.incident_title.delete(0, tk.END)
        self.incident_description.delete("1.0", tk.END)
        self.incident_indicators.delete("1.0", tk.END)
        self.refresh_incident_table()

    # ---------------- LOGS ----------------

    def build_logs_tab(self, parent):
        controls = ttk.Frame(parent)
        controls.pack(fill="x", pady=(0, 10))

        ttk.Button(
            controls,
            text="Activity Log",
            command=lambda: self.load_log_text(ACTIVITY_LOG),
        ).pack(side="left", padx=(0, 6))

        ttk.Button(
            controls,
            text="Security Log",
            command=lambda: self.load_log_text(SECURITY_LOG),
        ).pack(side="left", padx=6)

        self.log_text = tk.Text(parent, wrap="word")
        self.log_text.pack(fill="both", expand=True)

        self.load_log_text(ACTIVITY_LOG)

    def load_log_text(self, log_file):
        self.log_text.delete("1.0", tk.END)
        self.log_text.insert(tk.END, read_log(log_file))

    # ---------------- USER MANAGEMENT ----------------

    def build_users_tab(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill="x", pady=(0, 10))

        ttk.Label(
            top,
            text="User Accounts",
            style="Heading.TLabel",
        ).pack(side="left")

        ttk.Button(
            top,
            text="Create User",
            command=self.open_create_user_window,
        ).pack(side="right")

        columns = ("id", "username", "name", "role", "active")

        self.user_tree = ttk.Treeview(
            parent,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        for column, heading, width in (
            ("id", "ID", 60),
            ("username", "Username", 160),
            ("name", "Full Name", 220),
            ("role", "Role", 110),
            ("active", "Active", 90),
        ):
            self.user_tree.heading(column, text=heading)
            self.user_tree.column(column, width=width, anchor="w")

        self.user_tree.pack(fill="both", expand=True)

        actions = ttk.Frame(parent)
        actions.pack(fill="x", pady=(10, 0))

        ttk.Button(
            actions,
            text="Disable Selected",
            command=lambda: self.change_selected_user_status(False),
        ).pack(side="left", padx=(0, 6))

        ttk.Button(
            actions,
            text="Enable Selected",
            command=lambda: self.change_selected_user_status(True),
        ).pack(side="left", padx=6)

        ttk.Button(
            actions,
            text="Reset Password",
            command=self.reset_selected_password,
        ).pack(side="left", padx=6)

        self.refresh_user_table()

    def refresh_user_table(self):
        for item in self.user_tree.get_children():
            self.user_tree.delete(item)

        for user in list_users():
            self.user_tree.insert(
                "",
                "end",
                iid=str(user["id"]),
                values=(
                    user["id"],
                    user["username"],
                    user["full_name"],
                    user["role"],
                    "Yes" if user["is_active"] else "No",
                ),
            )

    def selected_user_id(self):
        selected = self.user_tree.selection()

        if not selected:
            messagebox.showwarning("No User", "Select a user first.")
            return None

        return int(selected[0])

    def open_create_user_window(self):
        window = tk.Toplevel(self.root)
        window.title("Create User")
        window.geometry("450x430")
        window.transient(self.root)
        window.grab_set()

        form = ttk.Frame(window, padding=20)
        form.pack(fill="both", expand=True)

        labels = ("Full Name", "Username", "Temporary Password")

        entries = []

        for row, label in enumerate(labels):
            ttk.Label(form, text=label).grid(
                row=row, column=0, sticky="w", padx=(0, 12), pady=8
            )

            entry = ttk.Entry(
                form,
                width=30,
                show="*" if label == "Temporary Password" else "",
            )
            entry.grid(row=row, column=1, pady=8)
            entries.append(entry)

        ttk.Label(form, text="Role").grid(
            row=3, column=0, sticky="w", padx=(0, 12), pady=8
        )
        role_box = ttk.Combobox(
            form,
            values=("analyst", "manager"),
            state="readonly",
        )
        role_box.set("analyst")
        role_box.grid(row=3, column=1, pady=8)

        def save_user():
            full_name, username, password = [
                entry.get() for entry in entries
            ]

            error = self.validate_account_data(
                full_name,
                username,
                password,
                password,
            )

            if error:
                messagebox.showerror(
                    "User Error",
                    error,
                    parent=window,
                )
                return

            try:
                create_user(
                    username=username,
                    full_name=full_name,
                    password=password,
                    role=role_box.get(),
                    must_change_password=True,
                )
            except sqlite3.IntegrityError:
                messagebox.showerror(
                    "User Error",
                    "Username already exists.",
                    parent=window,
                )
                return

            log_security(
                f"USER CREATED: {username.lower()} "
                f"by {self.current_user['username']}"
            )

            messagebox.showinfo(
                "User Created",
                "Account created. The user must change the temporary password.",
                parent=window,
            )

            window.destroy()
            self.refresh_user_table()

        ttk.Button(
            form,
            text="Create User",
            command=save_user,
        ).grid(
            row=4,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(20, 0),
        )

    def change_selected_user_status(self, active):
        user_id = self.selected_user_id()

        if user_id is None:
            return

        if user_id == self.current_user["id"] and not active:
            messagebox.showerror(
                "Not Allowed",
                "You cannot disable your own account.",
            )
            return

        set_user_active(user_id, active)

        log_security(
            f"USER {'ENABLED' if active else 'DISABLED'}: "
            f"ID {user_id} by {self.current_user['username']}"
        )

        self.refresh_user_table()

    def reset_selected_password(self):
        user_id = self.selected_user_id()

        if user_id is None:
            return

        new_password = simpledialog.askstring(
            "Reset Password",
            "Enter a temporary password:",
            show="*",
            parent=self.root,
        )

        if new_password is None:
            return

        if not self.password_is_valid(new_password):
            messagebox.showerror(
                "Weak Password",
                "Use at least 8 characters with uppercase, lowercase and a number.",
            )
            return

        reset_user_password(user_id, new_password)

        log_security(
            f"PASSWORD RESET: user ID {user_id} "
            f"by {self.current_user['username']}"
        )

        messagebox.showinfo(
            "Password Reset",
            "Temporary password saved. User must change it at next login.",
        )

    # ---------------- HELPERS ----------------

    def show_text_window(self, title, content):
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry("850x600")

        frame = ttk.Frame(window, padding=10)
        frame.pack(fill="both", expand=True)

        text = tk.Text(
            frame,
            wrap="word",
            font=("Consolas", 10),
        )
        text.pack(fill="both", expand=True)
        text.insert(tk.END, content)
        text.config(state="disabled")

    def validate_account_data(
        self,
        full_name,
        username,
        password,
        confirm,
    ):
        if not all((full_name.strip(), username.strip(), password, confirm)):
            return "Complete all fields."

        if len(username.strip()) < 4:
            return "Username must have at least 4 characters."

        if password != confirm:
            return "Passwords do not match."

        if not self.password_is_valid(password):
            return (
                "Password must contain at least 8 characters, "
                "an uppercase letter, a lowercase letter and a number."
            )

        return None

    @staticmethod
    def password_is_valid(password):
        return (
            len(password) >= 8
            and any(character.isupper() for character in password)
            and any(character.islower() for character in password)
            and any(character.isdigit() for character in password)
        )

    def logout(self):
        if messagebox.askyesno("Logout", "Sign out of CyberVault?"):
            log_security(
                f"LOGOUT: {self.current_user['username']}"
            )
            self.show_login()
