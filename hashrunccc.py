#  BCrypt Hash Cracker

# A Python tool for cracking BCrypt hashes using wordlist attacks.

# ## Features

# - BCrypt hash verification
# - Supports custom wordlists
# - Progress tracking
# - Time estimation
# - Simple CLI interface



## 2. bcrypt_cracker.py (Improved Version)

```python
#!/usr/bin/env python3
"""
BCrypt Hash Cracker Tool
Author: Your Name
GitHub: https://github.com/yourusername/bcrypt-hash-cracker
"""

import bcrypt
import time
import os
from argparse import ArgumentParser

def print_progress(attempts, password, start_time, total_passwords=None):
    """Display progress information"""
    elapsed = time.time() - start_time
    attempts_per_sec = attempts / elapsed if elapsed > 0 else 0
    
    progress_line = f"Attempt {attempts}: "
    if total_passwords:
        progress_line += f"{attempts/total_passwords:.1%} - "
    progress_line += f"{password[:20]}... [Elapsed: {elapsed:.1f}s, {attempts_per_sec:.1f} attempts/s]"
    
    print(progress_line, end='\r')

def crack_bcrypt_hash(target_hash, password_list_path, show_progress=True):
    """Attempt to crack a BCrypt hash using a wordlist"""
    try:
        # Validate inputs
        if not os.path.exists(password_list_path):
            raise FileNotFoundError(f"Password list not found at {password_list_path}")
        
        if isinstance(target_hash, str):
            target_hash = target_hash.encode('utf-8')

        # Read password list
        with open(password_list_path, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f]
            total_passwords = len(passwords)

        start_time = time.time()
        
        # Try each password
        for attempts, password in enumerate(passwords, 1):
            try:
                if show_progress and (attempts % 1000 == 0 or attempts == 1):
                    print_progress(attempts, password, start_time, total_passwords)
                
                if bcrypt.checkpw(password.encode('utf-8'), target_hash):
                    elapsed = time.time() - start_time
                    return {
                        'success': True,
                        'password': password,
                        'attempts': attempts,
                        'time_elapsed': elapsed,
                        'hashes_per_sec': attempts / elapsed if elapsed > 0 else 0
                    }
            except Exception:
                continue

        return {'success': False, 'attempts': attempts}

    except Exception as e:
        return {'error': str(e)}

def main():
    parser = ArgumentParser(description="BCrypt Hash Cracker Tool")
    parser.add_argument('--hash', help="BCrypt hash to crack")
    parser.add_argument('--wordlist', help="Path to wordlist file", 
                       default="/usr/share/wordlists/rockyou.txt")
    args = parser.parse_args()

    print("BCrypt Hash Cracker")
    print("-------------------\n")

    target_hash = args.hash or input("Enter the BCrypt hash to crack: ").strip()
    password_list_path = args.wordlist or input(
        "Enter path to password list (default: /usr/share/wordlists/rockyou.txt): "
    ).strip() or "/usr/share/wordlists/rockyou.txt"

    result = crack_bcrypt_hash(target_hash, password_list_path)
    
    if 'error' in result:
        print(f"\nError: {result['error']}")
    elif result['success']:
        print("\n\nSUCCESS! Password found!")
        print(f"Password: {result['password']}")
        print(f"Attempts: {result['attempts']}")
        print(f"Time elapsed: {result['time_elapsed']:.2f} seconds")
        print(f"Speed: {result['hashes_per_sec']:.2f} hashes/sec")
    else:
        print(f"\nPassword not found after {result['attempts']} attempts.")

if __name__ == "__main__":
    main()
