import tkinter as tk
from login_register import UserManager
from login_gui import LoginRegisterGUI
from dashboard_gui import DashboardGUI 
import subprocess

# --- Main Application Class ---
class SafeCryptApp:
  def __init__(self):
    self.root = tk.Tk()
    self.root.title("SafeCrypt")
    self.root.geometry("500x500")

    self.user_manager = UserManager()
    self.current_user = None # Store logged-in user

    # Initialize login GUI
    self.login_ui = LoginRegisterGUI(
      master=self.root,
      on_login=self.handle_login,
      on_register=self.handle_register
    )

  def handle_login(self, username, password):
    """Callback from login_gui -> attempt login"""
    status, msg = self.user_manager.login_user(username, password)
    if status:
      self.username = username
      self.password = password

      self.current_user = username
      print(f"Logged in as: {username}")
      # TODO: Transition to dashboard
      self.load_dashboard()
      return True, f"Welcome {username}!"
    else:
      return False, msg

  def handle_register(self, username, password, confirm_password):
    """Callback from login_gui -> attempt registration"""
    if password != confirm_password:
      return False, "Passwords do not match."

    status, msg = self.user_manager.register_user(username, password)
    if status:
      self.username = username
      self.password = password
      # TODO: Transition to dashboard
      self.load_dashboard()
      return True, msg
    else:
      return False, msg

  def load_dashboard(self):
    self.login_ui.container.destroy()

    self.root.title("SafeCrypt Dashboard Demo")
    self.root.geometry("850x600")
    # Pass None or a mock encryptor for demo
    self.dash = DashboardGUI(self.root, None, self.username)
    self.dash.pack(fill=tk.BOTH, expand=True)

  def run(self):
    self.root.mainloop()

if __name__ == "__main__":
  app = SafeCryptApp()
  app.run()
