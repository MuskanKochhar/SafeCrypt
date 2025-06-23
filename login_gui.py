import os
import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import ttkbootstrap as tb  # Modern themed widgets


class LoginRegisterGUI:
    def __init__(self, master, on_login, on_register):
        self.master = master
        self.master.title("🔒 SafeCrypt")
        self.master.geometry("460x500")
        self.master.resizable(False, False)
        self.style = tb.Style("cosmo")  # Try: 'litera', 'superhero', 'pulse', etc.

        self.on_login = on_login
        self.on_register = on_register

        # Container Frame
        self.container = tb.Frame(self.master, padding=20)
        self.container.place(relx=0.5, rely=0.5, anchor="center")

        self.logo_img = self.load_icon("safecrypt.png")  # Optional logo
        self.show_main_menu()

    def clear_container(self):
        try:
            if self.container and str(self.container) and self.container.winfo_exists():
                for widget in self.container.winfo_children():
                    widget.destroy()
        except Exception as e:
            print(f"[clear_container error]: {e}")

    def load_icon(self, path, size=(48, 48)):
        """Optional: Load an icon (PNG preferred)"""
        try:
            img = Image.open(path).resize(size, Image.ANTIALIAS)
            return ImageTk.PhotoImage(img)
        except Exception:
            return None

    def show_main_menu(self):
        if not self.container or not str(self.container) or not self.container.winfo_exists():
            return
        self.clear_container()
        if self.logo_img:
            tb.Label(self.container, image=self.logo_img).pack(pady=(0, 10))

        tb.Label(self.container, text="🔐 SafeCrypt", font=("Segoe UI", 22, "bold")).pack(pady=(10, 20))

        tb.Button(self.container, text="🔓 Login", bootstyle="success-outline", width=30,
                  command=self.show_login_form).pack(pady=10)

        tb.Button(self.container, text="📝 Register", bootstyle="info-outline", width=30,
                  command=self.show_register_form).pack(pady=10)

    def show_login_form(self):
        self.clear_container()
        tb.Label(self.container, text="🔓 Login", font=("Segoe UI", 16, "bold")).pack(pady=(10, 20))

        tb.Label(self.container, text="Username:").pack(anchor="w")
        self.login_username = tb.Entry(self.container, width=35)
        self.login_username.pack(pady=(0, 10))
        self.login_username.focus()

        tb.Label(self.container, text="Password:").pack(anchor="w")
        self.login_password = tb.Entry(self.container, show="*", width=35)
        self.login_password.pack(pady=(0, 20))

        tb.Button(self.container, text="✅ Submit", bootstyle="success", width=30,
                  command=self.handle_login).pack(pady=(0, 10))

        tb.Button(self.container, text="⬅ Back", bootstyle="secondary-outline", width=30,
                  command=self.show_main_menu).pack()

    def show_register_form(self):
        self.clear_container()
        tb.Label(self.container, text="📝 Register", font=("Segoe UI", 16, "bold")).pack(pady=(10, 20))

        tb.Label(self.container, text="Username:").pack(anchor="w")
        self.reg_username = tb.Entry(self.container, width=35)
        self.reg_username.pack(pady=(0, 10))
        self.reg_username.focus()

        tb.Label(self.container, text="Password:").pack(anchor="w")
        self.reg_password = tb.Entry(self.container, show="*", width=35)
        self.reg_password.pack(pady=(0, 10))

        tb.Label(self.container, text="Confirm Password:").pack(anchor="w")
        self.reg_confirm = tb.Entry(self.container, show="*", width=35)
        self.reg_confirm.pack(pady=(0, 20))

        tb.Button(self.container, text="📋 Register", bootstyle="info", width=30,
                  command=self.handle_register).pack(pady=(0, 10))

        tb.Button(self.container, text="⬅ Back", bootstyle="secondary-outline", width=30,
                  command=self.show_main_menu).pack()

    def handle_login(self):
        username = self.login_username.get().strip()
        password = self.login_password.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        success, msg = self.on_login(username, password)
        if success:
            messagebox.showinfo("Login Success", msg)
            self.show_main_menu()  # ✅ Go back to main menu, don't destroy
        else:
            messagebox.showerror("Login Failed", msg)

    def handle_register(self):
        username = self.reg_username.get().strip()
        password = self.reg_password.get().strip()
        confirm = self.reg_confirm.get().strip()

        if not username or not password or not confirm:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        success, msg = self.on_register(username, password, confirm)
        if success:
            messagebox.showinfo("Registration Success", msg)
            self.show_main_menu()  # ✅ Go back to main menu
        else:
            messagebox.showerror("Registration Failed", msg)


# ----------------- Example Usage -----------------
def dummy_login(username, password):
    return (username == "admin" and password == "admin123", "Welcome!" if username == "admin" else "Wrong credentials.")

def dummy_register(username, password, confirm):
    return True, "Registered successfully!"


if __name__ == "__main__":
    root = tb.Window(themename="cosmo")  # or superhero, flatly, litera, morph
    app = LoginRegisterGUI(root, dummy_login, dummy_register)
    root.mainloop()
