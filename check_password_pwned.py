import hashlib
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def check_password_pwned(password: str, timeout: float = 5.0, max_retries: int = 3) -> tuple:
    """
    Check if a password has been leaked before using the Have I Been Pwned API (k-anonymity).
    Returns (is_pwned: bool, count: int)

    Notes:
      - Sends only first 5 chars of SHA1 hash (secure method).
      - Requires: pip install requests
    """
    if not isinstance(password, str) or password == "":
        raise ValueError("Password must be a non-empty string")


    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    session = requests.Session()
    retries = Retry(total=max_retries, backoff_factor=0.5,
                    status_forcelist=(429, 500, 502, 503, 504),
                    allowed_methods=("GET",))
    session.mount("https://", HTTPAdapter(max_retries=retries))

    headers = {"User-Agent": "HIBP-Password-Check-Example/1.0 (Contact: you@example.com)"}

    try:
        response = session.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
    except requests.RequestException as e:
        raise RuntimeError(f"Network/API error: {e}") from e

    for line in response.text.splitlines():
        if ":" not in line:
            continue
        remote_suffix, count_str = line.split(":", 1)
        if remote_suffix.strip().upper() == suffix:
            try:
                return True, int(count_str.strip())
            except ValueError:
                return True, 1
    return False, 0
  #🔐 Password Leak Checker (Python)

#A simple Python script to check if a password has been leaked before using the **Have I Been Pwned API** securely (k-anonymity method).

#---

## 🧠 How It Works
#- Converts the password to a SHA1 hash.
#- Sends only the **first 5 characters** of the hash to the API.
#- Checks if the suffix exists in the response (secure and private).

#---

## 🚀 Usage
#```bash
# Install dependencies
#pip install -r requirements.txt

# Run example
#python example.py


#---

## 📦 Function Example
#```python
#from check_password_pwned import check_password_pwned

#is_pwned, count = check_password_pwned("password123")
#print(is_pwned, count)
#```

#---

## ⚠️ Privacy
#Your password **is never sent in full** — only the first 5 hash characters are shared.

#---

## 📝 License
#MIT License © 2025
  
