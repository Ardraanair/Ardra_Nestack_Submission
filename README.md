# Nestack Secure Records

A Flask-based cybersecurity application designed to securely store and manage confidential records using authentication, encryption and access control.

## 1. Project Overview

Nestack Secure Records is a web application developed using Python and Flask. It allows registered users to securely create, view and delete their personal records.

The application implements security mechanisms to protect user accounts and confidential information.

## 2. Technologies Used

- Python
- Flask
- SQLite
- HTML and CSS
- JavaScript
- Bcrypt
- Fernet Encryption
- Python-dotenv

## 3. Key Features

- **User Registration:** Allows new users to create accounts.
- **Secure Login:** Authenticates users using bcrypt password hashing.
- **Session Management:** Uses secure random session tokens with expiration.
- **Data Encryption:** Encrypts confidential record contents using Fernet.
- **Access Control:** Restricts users to accessing their own records.
- **Admin Access:** Supports administrator-level record retrieval.
- **Account Lockout:** Temporarily locks accounts after repeated failed login attempts.
- **Record Management:** Supports creating, viewing and deleting records.

## 4. Security Mechanisms

| Security mechanism | Purpose |
|---|---|
| Bcrypt hashing | Protects stored passwords |
| Fernet encryption | Protects confidential records |
| SHA-256 token hashing | Protects stored session tokens |
| Role-based access control | Distinguishes user and admin permissions |
| Ownership verification | Prevents unauthorized record access |
| Account lockout | Reduces repeated password guessing |
| Environment variables | Keeps encryption keys outside source code |

## 5. Project Structure

```text
myproject/
│
├── app.py
├── database.py
├── encryption.py
├── requirements.txt
├── .env
├── .gitignore
│
├── templates/
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   └── records.html
│
├── static/
│   ├── style.css
│   └── script.js
│
└── secure_records.db
```

**Note:** The `.env` file and database file are excluded from GitHub using `.gitignore`.

## 6. Installation and Execution

### Step 1: Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

### Step 2: Navigate to the project folder

```bash
cd myproject
```

### Step 3: Create a virtual environment

```bash
python -m venv .venv
```

### Step 4: Activate the environment

Windows:

```bash
.venv\Scripts\activate
```

### Step 5: Install dependencies

```bash
pip install -r requirements.txt
```

### Step 6: Configure environment variables

Create a `.env` file and configure the Fernet encryption key.

Generate a key using:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Add the generated key to `.env`:

```text
NESTACK_FERNET_KEY=your_generated_key
```

Never share or upload the actual encryption key.

### Step 7: Run the application

```bash
python app.py
```

Open the application at:

```text
http://127.0.0.1:5000
```

## 7. Threat Model

### Potential threats

1. **Brute-force attacks:** Attackers may repeatedly attempt to guess user passwords.
2. **Unauthorized access:** Users may attempt to access another user's records.
3. **Data exposure:** Confidential information may be exposed if stored without encryption.
4. **Password compromise:** Poor password storage practices may expose user credentials.
5. **Session misuse:** Stolen session tokens may be used to access accounts.
6. **Privilege escalation:** Users may attempt to register themselves with administrator privileges.

### Security measures

- Bcrypt password hashing protects stored passwords.
- Account lockout helps prevent repeated login attempts.
- Fernet encryption protects confidential record contents.
- Ownership checks restrict access to individual users' records.
- Hashed session tokens reduce exposure of stored session credentials.
- Registration does not allow users to assign themselves administrator roles.

## 8. Security Testing

The following checks have been performed during development:

- User registration and login.
- Password hashing.
- Record encryption and decryption.
- User-specific record access.
- Individual record retrieval.
- Administrator record retrieval.
- Unauthorized record access testing.
- Registration role-assignment restriction.
- Account lockout response verification (HTTP 429).

## 9. Future Enhancements

- Multi-factor authentication.
- Improved audit logging.
- Automated security testing.
- Enhanced administrator dashboard.
- Deployment with HTTPS and production-grade configuration.

## 10. Conclusion

Nestack Secure Records demonstrates the implementation of essential cybersecurity concepts in a web application. It combines authentication, encryption, session management and access control to provide a foundation for secure record management.
