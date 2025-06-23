import os
import pickle

USER_DATA_FILE = "userinfo.dat"

# --- User Manager Class ---
class UserManager:
  def __init__(self):
    self.users = self.load_users()

  def load_users(self):
    if os.path.exists(USER_DATA_FILE):
      with open(USER_DATA_FILE, "rb") as f:
        return pickle.load(f)
    return {}

  def save_users(self):
    with open(USER_DATA_FILE, "wb") as f:
      pickle.dump(self.users, f)

  def register_user(self, username, password):
    if username in self.users:
      return False, "Username already exists."
    self.users[username] = password
    self.save_users()
    return True, "Registration successful."

  def login_user(self, username, password):
    if username not in self.users:
      return False, "Username does not exist."
    if self.users[username] != password:
      return False, "Incorrect password."
    return True, "Login successful."