# SafeCrypt
Windows File Encryotion and Recovery System
## 🔐 Overview

**SafeCrypt** is a secure, GUI-based Windows application built using Python that allows users to encrypt, decrypt, and manage file visibility with ease. It combines cryptographic techniques with system-level operations to provide a powerful personal file security tool.  

Features include:
- **AES encryption and decryption** (CBC mode with random IVs)
- **User authentication** system
- **Dashboard GUI** for file/folder operations
- **PowerShell integration** for hiding/unhiding files
- **Per-user file tracking**

  ## 🧩 Project Structure

SafeCrypt/
│
├── main.py # Application launcher and logic flow
├── login_gui.py # Login and registration interface
├── dashboard_gui.py # Main dashboard interface
├── aes_enc_desc.py # AES encryption/decryption logic
├── powershell_util.py # File visibility toggling via PowerShell
├── userinfo.dat # Stores registered user info (Pickled)
├── trackdata.dat # Stores user file tracking data (Pickled)
└── README.md # Project documentation

## 🛠️ Technologies Used

- **Python 3.10+**
- **Tkinter** – For GUI components
- **PyCryptodome** – For AES encryption/decryption
- **Pickle** – For lightweight data persistence
- **PowerShell** – For Windows system-level file manipulation
- **os / subprocess** – For invoking system commands securely
