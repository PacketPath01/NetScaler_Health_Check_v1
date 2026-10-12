"""Desktop window for the NetScaler health check.

Launch with `python -m nshc.gui` or by double-clicking nshc_gui.pyw.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from nshc import __version__
from nshc.cli import decrypt_report, scan_bundles, summary_text
from nshc.crypto import CryptoError

BUNDLE_TYPES = [
    ("Support bundle", "*.tgz"),
    ("Tar archive", "*.tar *.gz"),
    ("ns.conf", "*.conf"),
    ("All files", "*.*"),
]
REPORT_TYPES = [("Encrypted report", "*.nshc"), ("All files", "*.*")]


class HealthCheckApp(ttk.Frame):
    def __init__(self, master: tk.Tk) -> None:
        super().__init__(master, padding=0)
        self.master = master
        self._busy = False
        self._last_html: Path | None = None
        self._scan_passphrase = ""
        self._build()

    def _build(self) -> None:
        header = tk.Frame(self, bg="#12324d", padx=20, pady=16)
        header.pack(fill="x")
        tk.Label(header, text="NetScaler Health Check", bg="#12324d", fg="white", font=("Segoe UI", 18, "bold")).pack(anchor="w")
        tk.Label(
            header,
            text=f"Offline advisory reports  ·  {__version__}  ·  nothing is uploaded",
            bg="#12324d",
            fg="#d5e2ec",
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 0))

        body = ttk.Frame(self, padding=16)
        body.pack(fill="both", expand=True)
        book = ttk.Notebook(body)
        book.pack(fill="both", expand=True)
        scan = ttk.Frame(book, padding=12)
        open_tab = ttk.Frame(book, padding=12)
        book.add(scan, text="Scan a bundle")
        book.add(open_tab, text="Open a report")
        self._build_scan(scan)
        self._build_open(open_tab)

        bar = ttk.Frame(body)
        bar.pack(fill="x", pady=(12, 0))
        ttk.Button(bar, text="Add to Desktop and Start menu", command=self._pin).pack(side="left")
        self.status = tk.Label(bar, text="", anchor="w", fg="#0d5c2e", font=("Segoe UI", 9))
        self.status.pack(side="left", padx=12)

    def _build_scan(self, parent: ttk.Frame) -> None:
        self.bundle = tk.StringVar()
        self.report = tk.StringVar()
        self.passphrase = tk.StringVar()
        self.confirm = tk.StringVar()
        self.plaintext = tk.BooleanVar(value=False)
        self.show_targets = tk.BooleanVar(value=True)
        self.show_pw = tk.BooleanVar(value=False)

        self._path_row(parent, 0, "Support bundle", self.bundle, self._browse_bundle)
        ttk.Button(parent, text="Choose folder…", command=self._browse_bundle_dir).grid(row=1, column=1, sticky="w", pady=(0, 8))
        self.report_label = ttk.Label(parent, text="Encrypted report")
        self.report_label.grid(row=2, column=0, sticky="w", pady=4)
        report_box = ttk.Frame(parent)
        report_box.grid(row=2, column=1, sticky="ew", pady=4)
        ttk.Entry(report_box, textvariable=self.report).pack(side="left", fill="x", expand=True)
        ttk.Button(report_box, text="Browse…", command=self._browse_report).pack(side="left", padx=(8, 0))

        self.pass_frame = ttk.Frame(parent)
        self.pass_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Label(self.pass_frame, text="Passphrase").grid(row=0, column=0, sticky="w", pady=4)
        self.pass_entry = ttk.Entry(self.pass_frame, textvariable=self.passphrase, show="*", width=40)
        self.pass_entry.grid(row=0, column=1, sticky="ew", padx=(12, 0), pady=4)
        ttk.Label(self.pass_frame, text="Confirm").grid(row=1, column=0, sticky="w", pady=4)
        self.confirm_entry = ttk.Entry(self.pass_frame, textvariable=self.confirm, show="*", width=40)
        self.confirm_entry.grid(row=1, column=1, sticky="ew", padx=(12, 0), pady=4)
        ttk.Checkbutton(self.pass_frame, text="Show", variable=self.show_pw, command=self._toggle_show).grid(row=0, column=2, padx=8)
        self.pass_frame.columnconfigure(1, weight=1)
        ttk.Label(self.pass_frame, text="At least 12 characters. A lost passphrase cannot be recovered.", foreground="#555").grid(row=2, column=1, sticky="w")

        ttk.Checkbutton(
            parent,
            text="Write an unencrypted HTML report instead (plaintext on disk)",
            variable=self.plaintext,
            command=self._toggle_plain,
        ).grid(row=4, column=1, sticky="w", pady=(10, 4))
        ttk.Checkbutton(
            parent,
            text="Show VIP name and the last two IP octets on each finding",
            variable=self.show_targets,
        ).grid(row=5, column=1, sticky="w")

        actions = ttk.Frame(parent)
        actions.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(8, 4))
        self.scan_button = ttk.Button(actions, text="Scan bundle", command=self._start_scan)
        self.scan_button.pack(side="left")
        self.open_button = ttk.Button(actions, text="Open the HTML report", command=self._open_last_html, state="disabled")
        self.open_button.pack(side="left", padx=8)
        self.progress = ttk.Progressbar(actions, mode="indeterminate", length=180)
        self.progress.pack(side="left", padx=8)

        self.summary = self._log(parent, row=7)
        parent.columnconfigure(1, weight=1)
        parent.rowconfigure(7, weight=1)

    def _build_open(self, parent: ttk.Frame) -> None:
        self.open_report = tk.StringVar()
        self.open_dir = tk.StringVar()
        self.open_pass = tk.StringVar()
        self._path_row(parent, 0, "Encrypted report", self.open_report, self._browse_existing_report)
        folder = ttk.Frame(parent)
        folder.grid(row=1, column=0, columnspan=2, sticky="ew", pady=4)
        ttk.Label(folder, text="Decrypt into").pack(side="left")
        ttk.Entry(folder, textvariable=self.open_dir).pack(side="left", fill="x", expand=True, padx=12)
        ttk.Button(folder, text="Browse…", command=self._browse_open_dir).pack(side="left")
        pw = ttk.Frame(parent)
        pw.grid(row=2, column=0, columnspan=2, sticky="ew", pady=4)
        ttk.Label(pw, text="Passphrase").pack(side="left")
        self.open_pass_entry = ttk.Entry(pw, textvariable=self.open_pass, show="*", width=40)
        self.open_pass_entry.pack(side="left", padx=12)
        actions = ttk.Frame(parent)
        actions.grid(row=3, column=0, columnspan=2, sticky="w", pady=8)
        self.open_tab_button = ttk.Button(actions, text="Decrypt and open", command=self._start_open)
        self.open_tab_button.pack(side="left")
        self.open_progress = ttk.Progressbar(actions, mode="indeterminate", length=180)
        self.open_progress.pack(side="left", padx=8)
        ttk.Label(
            parent,
            text="The decrypted HTML and JSON are plaintext. Delete that folder when you are finished.",
            wraplength=640,
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(4, 8))
        self.open_log = self._log(parent, row=5)
        parent.columnconfigure(1, weight=1)
        parent.rowconfigure(5, weight=1)

    def _path_row(self, parent: ttk.Frame, row: int, label: str, variable: tk.StringVar, command) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=4, padx=(0, 12))
        box = ttk.Frame(parent)
        box.grid(row=row, column=1, sticky="ew", pady=4)
        ttk.Entry(box, textvariable=variable).pack(side="left", fill="x", expand=True)
        ttk.Button(box, text="Browse…", command=command).pack(side="left", padx=(8, 0))

    def _log(self, parent: ttk.Frame, row: int) -> tk.Text:
        widget = tk.Text(parent, height=14, wrap="word", font=("Consolas", 10), state="disabled", relief="solid", borderwidth=1)
        widget.grid(row=row, column=0, columnspan=2, sticky="nsew", pady=(8, 0))
        return widget

    def _set_text(self, widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _set_status(self, text: str, error: bool = False) -> None:
        self.status.configure(text=text, fg="#8a1f11" if error else "#0d5c2e")

    def _toggle_show(self) -> None:
        show = "" if self.show_pw.get() else "*"
        self.pass_entry.configure(show=show)
        self.confirm_entry.configure(show=show)
        self.open_pass_entry.configure(show=show)

    def _toggle_plain(self) -> None:
        if self.plaintext.get():
            self.pass_frame.grid_remove()
            self.report_label.configure(text="Report folder")
            current = self.report.get()
            if current.lower().endswith(".nshc"):
                self.report.set(str(Path(current).with_suffix("")))
        else:
            self.pass_frame.grid()
            self.report_label.configure(text="Encrypted report")
            current = self.report.get()
            if current and not current.lower().endswith(".nshc"):
                self.report.set(current + ".nshc")

    def _browse_bundle(self) -> None:
        selected = filedialog.askopenfilename(title="Support bundle", filetypes=BUNDLE_TYPES)
        if selected:
            self._set_bundle(selected)

    def _browse_bundle_dir(self) -> None:
        selected = filedialog.askdirectory(title="Collector folder")
        if selected:
            self._set_bundle(selected)

    def _set_bundle(self, selected: str) -> None:
        self.bundle.set(selected)
        if self.report.get():
            return
        source = Path(selected)
        target = source.with_name(f"{source.stem}-healthcheck.nshc")
        self.report.set(str(target))

    def _browse_report(self) -> None:
        if self.plaintext.get():
            selected = filedialog.askdirectory(title="Folder for the plaintext report")
            if selected:
                self.report.set(selected)
            return
        selected = filedialog.asksaveasfilename(title="Encrypted report", defaultextension=".nshc", filetypes=REPORT_TYPES)
        if selected:
            self.report.set(selected)

    def _browse_existing_report(self) -> None:
        selected = filedialog.askopenfilename(title="Encrypted report", filetypes=REPORT_TYPES)
        if not selected:
            return
        self.open_report.set(selected)
        if not self.open_dir.get():
            path = Path(selected)
            self.open_dir.set(str(path.with_suffix("")))

    def _browse_open_dir(self) -> None:
        selected = filedialog.askdirectory(title="Folder for the decrypted report")
        if selected:
            self.open_dir.set(selected)

    def _start_scan(self) -> None:
        if self._busy:
            return
        bundle = self.bundle.get().strip()
        report = self.report.get().strip()
        if not bundle:
            self._set_status("Choose a support bundle.", error=True)
            return
        if not report:
            self._set_status("Choose where to write the report.", error=True)
            return
        passphrase = ""
        if not self.plaintext.get():
            passphrase = self.passphrase.get()
            if passphrase != self.confirm.get():
                self._set_status("Passphrases do not match.", error=True)
                return
        destination = Path(report)
        if destination.exists() and not messagebox.askyesno("Replace report", f"{destination.name} already exists. Replace it?"):
            return
        self._scan_passphrase = passphrase
        self._busy = True
        self._last_html = None
        self.scan_button.configure(state="disabled")
        self.open_button.configure(state="disabled")
        self.progress.start(12)
        self._set_status("Reading the support bundle…")
        self._set_text(self.summary, "Scanning. A large collector can take a minute.\n")
        threading.Thread(
            target=self._scan_worker,
            args=(Path(bundle), destination, passphrase, self.plaintext.get(), self.show_targets.get()),
            daemon=True,
        ).start()

    def _scan_worker(self, bundle: Path, report: Path, passphrase: str, plaintext: bool, show_targets: bool) -> None:
        try:
            document = scan_bundles(
                [bundle],
                report,
                passphrase=passphrase,
                plaintext=plaintext,
                show_targets=show_targets,
            )
        except (CryptoError, ValueError, OSError) as exc:
            message = str(exc)
            self.after(0, lambda message=message: self._scan_done(error=message))
            return
        text = summary_text(document)
        if plaintext:
            text = f"Plaintext report:\n{report / 'report.html'}\nDelete this folder when you are finished.\n{text}"
            html = report / "report.html"
        else:
            text = f"Encrypted report:\n{report}\nUse Open the HTML report when you want the full findings.\n{text}"
            html = None
        self.after(0, lambda text=text, html=html: self._scan_done(text=text, html=html))

    def _scan_done(self, text: str = "", html: Path | None = None, error: str = "") -> None:
        self.progress.stop()
        self._busy = False
        self.scan_button.configure(state="normal")
        if error:
            self._set_status(error, error=True)
            self._set_text(self.summary, error)
            return
        self._last_html = html
        self.open_button.configure(state="normal")
        self._set_status("Scan finished.")
        self._set_text(self.summary, text)

    def _open_last_html(self) -> None:
        if self._last_html and self._last_html.is_file():
            webbrowser.open(self._last_html.resolve().as_uri())
            return
        report = self.report.get().strip()
        if not report or not self._scan_passphrase:
            self._set_status("Scan with a passphrase first, or use the Open a report tab.", error=True)
            return
        destination = Path(report).with_suffix("")
        self._set_status("Decrypting the report…")
        self._decrypt_and_open(Path(report), destination, self._scan_passphrase, self.summary)

    def _start_open(self) -> None:
        if self._busy:
            return
        report = self.open_report.get().strip()
        folder = self.open_dir.get().strip()
        passphrase = self.open_pass.get()
        if not report or not folder:
            self._set_status("Choose a report and a folder.", error=True)
            return
        self._busy = True
        self.open_tab_button.configure(state="disabled")
        self.open_progress.start(12)
        self._set_status("Decrypting…")
        self._decrypt_and_open(Path(report), Path(folder), passphrase, self.open_log, progress=self.open_progress, button=self.open_tab_button)

    def _decrypt_and_open(self, report: Path, folder: Path, passphrase: str, log: tk.Text, progress: ttk.Progressbar | None = None, button: ttk.Button | None = None) -> None:
        def worker() -> None:
            try:
                html = decrypt_report(report, folder, passphrase)
            except (CryptoError, ValueError, OSError) as exc:
                message = str(exc)
                self.after(0, lambda message=message: finish(error=message))
                return
            self.after(0, lambda html=html: finish(html=html))

        def finish(html: Path | None = None, error: str = "") -> None:
            self._busy = False
            if progress is not None:
                progress.stop()
            if button is not None:
                button.configure(state="normal")
            if error:
                self._set_status(error, error=True)
                self._set_text(log, error)
                return
            assert html is not None
            self._last_html = html
            self.open_button.configure(state="normal")
            self._set_status("Report opened in the browser. Delete the decrypted folder when you are done.")
            self._set_text(log, f"Decrypted report:\n{html}\n\nThis folder is plaintext. Delete it when you are finished.")
            webbrowser.open(html.resolve().as_uri())

        self._busy = True
        threading.Thread(target=worker, daemon=True).start()

    def _pin(self) -> None:
        try:
            created = create_shortcuts()
        except (OSError, subprocess.CalledProcessError) as exc:
            messagebox.showerror("Shortcut", str(exc))
            return
        messagebox.showinfo("Shortcut", "Created:\n" + "\n".join(str(path) for path in created))


def create_shortcuts() -> list[Path]:
    """Add Desktop and Start menu shortcuts that open this window."""
    if getattr(sys, "frozen", False):
        target = Path(sys.executable).resolve()
        workdir = target.parent
        arguments = ""
    else:
        launcher = Path(__file__).resolve().parents[1] / "nshc_gui.pyw"
        if not launcher.is_file():
            raise OSError(f"Launcher not found: {launcher}")
        target = Path(sys.executable).with_name("pythonw.exe")
        if not target.is_file():
            target = Path(sys.executable)
        workdir = launcher.parent
        arguments = f'"{launcher}"'
    folders = _special_folders()
    created: list[Path] = []
    for folder in folders:
        folder.mkdir(parents=True, exist_ok=True)
        destination = folder / "NetScaler Health Check.lnk"
        _write_shortcut(destination, target, arguments, workdir)
        created.append(destination)
    return created


def _special_folders() -> list[Path]:
    command = "[Environment]::GetFolderPath('Desktop'); [Environment]::GetFolderPath('Programs')"
    output = subprocess.check_output(["powershell", "-NoProfile", "-Command", command], text=True)
    folders = [Path(line.strip()) for line in output.splitlines() if line.strip()]
    if len(folders) < 2:
        raise OSError("Could not find the Desktop or Start menu folder.")
    return folders[:2]


def _write_shortcut(destination: Path, target: Path, arguments: str, workdir: Path) -> None:
    env = os.environ.copy()
    env.update(
        {
            "NSHC_LINK": str(destination),
            "NSHC_PYTHONW": str(target),
            "NSHC_ARGS": arguments,
            "NSHC_WORKDIR": str(workdir),
        }
    )
    script = (
        "$shell = New-Object -ComObject WScript.Shell; "
        "$lnk = $shell.CreateShortcut($env:NSHC_LINK); "
        "$lnk.TargetPath = $env:NSHC_PYTHONW; "
        "$lnk.Arguments = $env:NSHC_ARGS; "
        "$lnk.WorkingDirectory = $env:NSHC_WORKDIR; "
        "$lnk.Description = 'NetScaler support-bundle health check'; "
        "$lnk.Save()"
    )
    subprocess.run(["powershell", "-NoProfile", "-Command", script], check=True, env=env, capture_output=True)


def main() -> None:
    root = tk.Tk()
    root.title("NetScaler Health Check")
    root.geometry("860x700")
    root.minsize(720, 560)
    style = ttk.Style()
    if "vista" in style.theme_names():
        style.theme_use("vista")
    app = HealthCheckApp(root)
    app.pack(fill="both", expand=True)
    root.mainloop()


if __name__ == "__main__":
    main()
