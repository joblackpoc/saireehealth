from cryptography.fernet import Fernet
def ensure_fernet_key(existing=None):
    if existing:
        return existing
    return Fernet.generate_key().decode()
