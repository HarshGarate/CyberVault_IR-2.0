import tkinter as tk

from config import create_project_folders
from database import create_database
from gui import CyberVaultApp


def main():
    create_project_folders()
    create_database()

    root = tk.Tk()
    CyberVaultApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
