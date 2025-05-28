# 🔐 SecureShareApp — Secure Encrypted File Storage & Sharing System

## 📘 Overview

**SecureShareApp** is a secure web application that enables users to upload, encrypt, download, and manage their files within a role-controlled environment. It is built using the Flask web framework and integrates essential security features such as:

* User authentication and registration
* File encryption using the **Fernet** symmetric cryptography system
* **MFA (Multi-Factor Authentication)** using **TOTP** (Time-Based One-Time Password)
* Role-Based Access Control (**RBAC**) with Admin/User privileges
* Secure session management using Flask-Login
* Admin dashboard for user and file management

---

## 🧱 Key Components

### 1. **User Authentication & Authorization**

* **Login/Registration**: Users can register and login using username/email and password.
* **Password Hashing**: Passwords are securely hashed using Werkzeug.
* **Session Management**: Managed by Flask-Login with secure session cookies.
* **RBAC**: Users are assigned either a `user` or `admin` role. Admins can view all users and files, while regular users can only access their own.

---

### 2. **Multi-Factor Authentication (MFA)**

* **MFA Setup**:

  * Users generate a TOTP secret via `pyotp`.
  * A QR code is rendered using `qrcode` that can be scanned with apps like **Google Authenticator**.
  * Once verified, the secret is stored in the database.

* **MFA Verification on Login**:

  * If a user has MFA enabled, they're required to enter the 6-digit token from their authenticator app to complete login.
  * This prevents unauthorized access even if the password is compromised.

---

### 3. **File Encryption & Storage**

* **Encryption Method**:

  * Files are encrypted using `cryptography.Fernet` before being saved to disk.
  * A key is generated and stored locally in `secret.key`.

* **Secure Uploads**:

  * Files are uploaded via a form, read into memory, encrypted, and then saved to the `user_uploads_encrypted/` directory using the user’s ID and the filename.

* **Secure Downloads**:

  * When a user downloads a file, it is decrypted in memory and sent as a download via Flask’s `send_file`.

* **Deletion**:

  * Users and admins can delete files.
  * The file is deleted from both the database and the file system.

---

### 4. **Admin Dashboard**

Admins have access to a special dashboard that allows them to:

* View a list of all registered users.
* View all uploaded files.
* Delete any user's file if needed.
* Manage RBAC permissions (extendable).

---

### 5. **Database Design**

Using **Flask-SQLAlchemy**, the app has the following models:

#### `User`

* `id`
* `username`
* `email`
* `password_hash`
* `role` (admin/user)
* `mfa_enabled`
* `mfa_secret`

#### `File`

* `id`
* `filename`
* `filepath_encrypted`
* `upload_date`
* `user_id` (foreign key)

Relationships:

* Each `User` can have multiple `File` records.

---

### 6. **Security Best Practices Implemented**

✅ Encrypted file storage
✅ Secure password hashing
✅ Multi-factor authentication
✅ Session protection
✅ Role-based access
✅ Minimal data exposure
✅ No sensitive data in URLs
✅ Flash messages for feedback
✅ `secure_filename()` usage to prevent path traversal
✅ `.gitignore` to avoid sensitive files (e.g. `secret.key`, uploads) in version control

---

## 📁 File Structure

```plaintext
secure-share-app/
│
├── app.py                      # Main application file
├── forms.py                    # Flask-WTF forms
├── models.py                   # SQLAlchemy models
├── templates/                  # HTML templates
│   ├── login.html
│   ├── register.html
│   ├── index.html
│   ├── upload_file.html
│   ├── setup_mfa.html
│   ├── verify_mfa_login.html
│   └── admin_dashboard.html
├── static/                     # Static files (optional CSS, JS)
├── requirements.txt            # Dependencies
├── secret.key                  # Encryption key (in .gitignore)
├── user_uploads_encrypted/     # Encrypted file storage (in .gitignore)
├── instance/                   # SQLite database (in .gitignore)
├── .gitignore
└── README.md
```

---

## ⚙️ How It Works

1. **User Registers** → Password is hashed → Account created.
2. **User Logs In**:

   * If MFA is enabled → MFA code is requested.
   * If MFA is correct → User logs in.
3. **User Uploads File** → File is encrypted → Saved securely on disk.
4. **User Downloads File** → File is decrypted in memory → Served as download.
5. **Admin Logs In** → Access to all files and users.
6. **MFA Setup** → QR code shown → User scans with Google Authenticator → Code verified → MFA enabled.

---
## 🧪 Setup Instructions

### 1. Create a Virtual Environment
```
sudo apt install python3 python3-pip
python3 -m venv venv
source venv/bin/activate  # macOS/Linux
# OR
venv\Scripts\activate     # Windows
```
### 2. Install Python Dependencies
```
pip install -r requirements.txt
```

### 3.Run
```
python app.py 
```
* ✅ Dockerize the application
* ✅ Environment-based configuration (`.env`)
* ✅ Use PostgreSQL for production

---
