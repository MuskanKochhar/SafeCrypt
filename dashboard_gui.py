import os
import json
import subprocess
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox
from tkinter import filedialog, simpledialog
from aes_enc_desc import encrypt_file, decrypt_file


class DashboardApp(tb.Window):
    def __init__(self, encryptor, username):
        super().__init__(themename="superhero")
        self.title("SafeCrypt Encryption Dashboard")
        self.geometry("1080x640")
        self.resizable(True, True)

        self.main_frame = DashboardGUI(self, encryptor, username)
        self.main_frame.pack(fill="both", expand=True, padx=15, pady=10)

        self.mainloop()


class DashboardGUI(tb.Frame):
    def __init__(self, parent, encryptor, username, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.encryptor = encryptor
        self.username = username
        self.tracked_items = []
        self.selected_item = None
        self.trackfile_path = "trackdata.dat"

        self.create_widgets()
        self.load_tracked_items()

    def create_widgets(self):
        # Title
        title = tb.Label(self, text="🔐 SafeCrypt Dashboard", font=("Segoe UI", 20, "bold"), bootstyle="primary")
        title.pack(pady=(10, 5))

        # Treeview
        columns = ("Name", "Location", "Status", "Visibility", "Key Used")
        self.tree = tb.Treeview(self, columns=columns, show="headings", bootstyle="dark")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="w", width=180)
        self.tree.pack(fill="both", expand=True, padx=15, pady=10)
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        # Button Panel
        btn_frame = tb.Frame(self)
        btn_frame.pack(pady=10)

        self.btn_add = tb.Button(btn_frame, text="➕ Add File/Folder", width=20, bootstyle="success", command=self.add_item)
        self.btn_remove = tb.Button(btn_frame, text="🗑 Remove Selected", width=20, bootstyle="danger", command=self.remove_item, state=DISABLED)
        self.btn_open_details = tb.Button(btn_frame, text="📂 Open Details", width=20, bootstyle="info", command=self.open_details_panel, state=DISABLED)

        self.btn_add.grid(row=0, column=0, padx=8)
        self.btn_remove.grid(row=0, column=1, padx=8)
        self.btn_open_details.grid(row=0, column=2, padx=8)

        self.details_panel = None

    def on_tree_select(self, event):
        selected = self.tree.selection()
        self.selected_item = selected[0] if selected else None
        state = NORMAL if self.selected_item else DISABLED
        self.btn_remove.config(state=state)
        self.btn_open_details.config(state=state)

    def add_item(self):
        choice = Messagebox.yesno("Add Item", "Add a file?\n(Click No to add a folder)")
        path = filedialog.askopenfilename() if choice else filedialog.askdirectory()
        if not path:
            return

        name = os.path.basename(path)
        item_data = {
            "name": name,
            "location": path,
            "status": "Decrypted",
            "visibility": "Visible",
            "key_used": "-",
            "path": path,
            "is_folder": not choice,
            "encrypted": False,
            "hidden": False,
            "key": None,
            "editable": True,
        }

        self.tracked_items.append(item_data)
        self.tree.insert("", "end", values=(name, path, "Decrypted", "Visible", "-"))
        self.save_tracked_items()

    def remove_item(self):
        if not self.selected_item:
            return
        index = self.tree.index(self.selected_item)
        self.tree.delete(self.selected_item)
        del self.tracked_items[index]
        self.selected_item = None
        self.btn_remove.config(state=DISABLED)
        self.btn_open_details.config(state=DISABLED)
        if self.details_panel:
            self.details_panel.destroy()
            self.details_panel = None
        self.save_tracked_items()

    def open_details_panel(self):
        if not self.selected_item:
            return
        if self.details_panel:
            self.details_panel.destroy()

        index = self.tree.index(self.selected_item)
        item = self.tracked_items[index]

        self.details_panel = tb.LabelFrame(self, text="File Details", bootstyle="secondary")
        self.details_panel.pack(fill="x", padx=15, pady=10)

        tb.Label(self.details_panel, text=f"📄 Name: {item['name']}", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        tb.Label(self.details_panel, text=f"📁 Location: {item['location']}", wraplength=800).pack(anchor="w")
        tb.Label(self.details_panel, text=f"📂 Type: {'Folder' if item['is_folder'] else 'File'}").pack(anchor="w")
        tb.Label(self.details_panel, text=f"🔐 Status: {'Encrypted' if item['encrypted'] else 'Decrypted'}").pack(anchor="w")
        tb.Label(self.details_panel, text=f"👁 Visibility: {'Hidden' if item['hidden'] else 'Visible'}").pack(anchor="w")
        tb.Label(self.details_panel, text=f"🔑 Key Used: {item['key'] if item['key'] else '-'}").pack(anchor="w")

        action_frame = tb.Frame(self.details_panel)
        action_frame.pack(pady=10)

        tb.Button(action_frame, text="Encrypt", width=14, bootstyle="success",
                  command=lambda: self.encrypt_item(index),
                  state=DISABLED if item['encrypted'] else NORMAL).grid(row=0, column=0, padx=5)

        tb.Button(action_frame, text="Decrypt", width=14, bootstyle="danger",
                  command=lambda: self.decrypt_item(index),
                  state=DISABLED if not item['encrypted'] else NORMAL).grid(row=0, column=1, padx=5)

        tb.Button(action_frame, text="Hide" if not item['hidden'] else "Unhide", width=14, bootstyle="warning",
                  command=lambda: self.toggle_visibility(index)).grid(row=0, column=2, padx=5)

        tb.Button(action_frame, text="Lock Editing" if item['editable'] else "Unlock Editing", width=16,
                  bootstyle="info", command=lambda: self.toggle_editability(index)).grid(row=0, column=3, padx=5)

    def encrypt_item(self, index):
        item = self.tracked_items[index]
        key = self.ask_key()
        if not key:
            return
        success = encrypt_file(item['path'], key)
        if success:
            item['encrypted'] = True
            item['key'] = key
            self.update_treeview_item(index)
            self.save_tracked_items()
            Messagebox.ok("Encrypted", f"{item['name']} encrypted.")
            self.open_details_panel()
        else:
            Messagebox.showerror("Encryption Failed", f"Failed to encrypt {item['name']}.")

    def decrypt_item(self, index):
        item = self.tracked_items[index]
        key = item['key']
        if not key:
            Messagebox.showerror("Missing Key", "No key available for decryption.")
            return
        success = decrypt_file(item['path'], key)
        if success:
            item['encrypted'] = False
            item['key'] = None
            self.update_treeview_item(index)
            self.save_tracked_items()
            Messagebox.ok("Decrypted", f"{item['name']} decrypted.")
            self.open_details_panel()
        else:
            Messagebox.showerror("Decryption Failed", f"Failed to decrypt {item['name']}.")

    def toggle_visibility(self, index):
        item = self.tracked_items[index]
        new_state = not item['hidden']
        self.set_visibility(item['path'], hide=new_state)
        item['hidden'] = new_state
        self.update_treeview_item(index)
        self.save_tracked_items()
        self.open_details_panel()

    def toggle_editability(self, index):
        item = self.tracked_items[index]
        item['editable'] = not item['editable']
        try:
            action = "lock" if not item['editable'] else "unlock"
            subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", "file_lock.ps1", item['path'], action], check=True)
        except Exception as e:
            Messagebox.showerror("Error", f"Edit toggle failed: {e}")
            item['editable'] = not item['editable']
        self.save_tracked_items()
        self.open_details_panel()

    def ask_key(self):
        return simpledialog.askstring("Key", "Enter encryption key name:")

    def update_treeview_item(self, index):
        item = self.tracked_items[index]
        values = (
            item['name'],
            item['location'],
            "Encrypted" if item['encrypted'] else "Decrypted",
            "Hidden" if item['hidden'] else "Visible",
            item['key'] if item['key'] else "-"
        )
        tree_id = self.tree.get_children()[index]
        self.tree.item(tree_id, values=values)

    def save_tracked_items(self):
        try:
            all_data = {}
            if os.path.exists(self.trackfile_path):
                with open(self.trackfile_path, "r") as f:
                    all_data = json.load(f)
            all_data[self.username] = self.tracked_items
            with open(self.trackfile_path, "w") as f:
                json.dump(all_data, f, indent=2)
        except Exception as e:
            Messagebox.showerror("Error", f"Save failed: {str(e)}")

    def load_tracked_items(self):
        if not os.path.exists(self.trackfile_path):
            return
        try:
            with open(self.trackfile_path, "r") as f:
                all_data = json.load(f)
            self.tracked_items = all_data.get(self.username, [])
            for item in self.tracked_items:
                values = (
                    item['name'],
                    item['location'],
                    "Encrypted" if item['encrypted'] else "Decrypted",
                    "Hidden" if item['hidden'] else "Visible",
                    item['key'] if item['key'] else "-"
                )
                self.tree.insert("", "end", values=values)
        except Exception as e:
            Messagebox.showerror("Error", f"Load failed: {str(e)}")

    def set_visibility(self, path, hide=True):
        script_path = os.path.abspath("visibility_utils.ps1")
        action = "hide" if hide else "unhide"
        try:
            result = subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", script_path, "-Path", path, "-Action", action],
                                    capture_output=True, text=True)
            if result.returncode != 0:
                Messagebox.showerror("Error", result.stdout)
        except Exception as e:
            Messagebox.showerror("Error", f"Visibility exception: {str(e)}")

