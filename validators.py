import re
def validate_password(password: str) -> bool:
    isValidLength = len(password) >= 8
    hasUppercase = any(char.isupper() for char in password)
    hasLowercase = any(char.islower() for char in password)
    hasDigit = any(char.isdigit() for char in password)
    hasChar = any(char.isalpha() for char in password)
    return isValidLength and hasUppercase and hasLowercase and hasDigit and hasChar

def validate_email(email: str) -> bool:
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None

