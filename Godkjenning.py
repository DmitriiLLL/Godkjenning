import hashlib
import os
import hmac
import time
import random

class User:
    """Represents a single user with password hash, 2FA status and OTP metadata."""
    def __init__(self, username: str, salt: bytes, password_hash: bytes, two_factor: bool = True):
        self.username = username
        self.salt = salt
        self.password_hash = password_hash
        self.two_factor = two_factor
        self.failed_attempts = 0
        self.locked_until = 0  # timestamp until which account is locked
        self.pending_otp = None
        self.otp_expiry = 0

class AuthSystem:
    """Two-factor authentication system using OTP codes."""
    def __init__(self, lockout_threshold=3, lockout_duration=60, otp_ttl=300):
        self.users = {}  # username -> User
        self.lockout_threshold = lockout_threshold
        self.lockout_duration = lockout_duration
        self.otp_ttl = otp_ttl  # OTP time-to-live in seconds

    def _hash_password(self, password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000)

    def register_user(self, username: str, password: str, two_factor: bool = True) -> bool:
        if username in self.users:
            print(f"[ERROR] User '{username}' already exists.")
            return False
        salt = os.urandom(16)
        pwd_hash = self._hash_password(password, salt)
        self.users[username] = User(username, salt, pwd_hash, two_factor)
        print(f"[INFO] User '{username}' registered successfully. 2FA={'enabled' if two_factor else 'disabled'}.")
        return True

    def _generate_otp(self, user: User) -> None:
        otp = '{:06d}'.format(random.randint(0, 999999))
        user.pending_otp = otp
        user.otp_expiry = time.time() + self.otp_ttl
        # Simulate sending OTP
        print(f"[OTP SENT] Code for '{user.username}': {otp} (valid {self.otp_ttl//60} min)")

    def authenticate_user(self, username: str, password: str) -> bool:
        user = self.users.get(username)
        now = time.time()
        if user is None:
            print(f"[ERROR] User '{username}' not found.")
            return False
        if now < user.locked_until:
            print(f"[WARN] Account '{username}' is locked until {time.ctime(user.locked_until)}.")
            return False
        # Verify password
        attempted_hash = self._hash_password(password, user.salt)
        if not hmac.compare_digest(attempted_hash, user.password_hash):
            user.failed_attempts += 1
            print(f"[ERROR] Authentication failed for '{username}'. Attempts: {user.failed_attempts}")
            if user.failed_attempts >= self.lockout_threshold:
                user.locked_until = now + self.lockout_duration
                print(f"[WARN] Account '{username}' locked until {time.ctime(user.locked_until)}.")
            return False
        # Password correct
        user.failed_attempts = 0
        print(f"[INFO] Password verified for '{username}'.")
        # Handle 2FA
        if user.two_factor:
            self._generate_otp(user)
            entered = input("Enter OTP: ").strip()
            if time.time() > user.otp_expiry or entered != user.pending_otp:
                print(f"[ERROR] Invalid or expired OTP for '{username}'.")
                return False
            print(f"[INFO] Two-factor authentication successful for '{username}'.")
        return True

    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        if self.authenticate_user(username, old_password):
            user = self.users[username]
            salt = os.urandom(16)
            pwd_hash = self._hash_password(new_password, salt)
            user.salt = salt
            user.password_hash = pwd_hash
            print(f"[INFO] Password changed successfully for '{username}'.")
            return True
        return False

# ---------------------------------------
# Interactive CLI
# ---------------------------------------

def main():
    auth = AuthSystem(lockout_threshold=3, lockout_duration=60, otp_ttl=300)
    while True:
        print("\n--- Two-Factor Auth System ---")
        print("1) Register")
        print("2) Login")
        print("3) Change Password")
        print("4) Exit")
        choice = input("Select an option: ").strip()

        if choice == '1':
            username = input("Enter new username: ").strip()
            password = input("Enter new password: ").strip()
            tf = input("Enable 2FA? (y/N): ").strip().lower() == 'y'
            auth.register_user(username, password, two_factor=tf)

        elif choice == '2':
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            auth.authenticate_user(username, password)

        elif choice == '3':
            username = input("Username: ").strip()
            old_password = input("Current password: ").strip()
            new_password = input("New password: ").strip()
            auth.change_password(username, old_password, new_password)

        elif choice == '4':
            print("Exiting. Goodbye!")
            break

        else:
            print("[ERROR] Invalid option. Please select 1-4.")

if __name__ == '__main__':
    main()