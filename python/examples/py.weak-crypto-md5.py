#!/usr/bin/env python3
"""
Example code that demonstrates the py.weak-crypto-md5 rule violation.
This code should trigger the security rule.
"""

import hashlib

def unsafe_md5_example():
    """This function demonstrates unsafe MD5 usage."""
    password = "user_password"
    hash_obj = hashlib.md5(password.encode())  # This will trigger the rule
    return hash_obj.hexdigest()

def another_unsafe_md5_example():
    """Another example of unsafe MD5 usage."""
    data = "sensitive_data"
    md5_hash = hashlib.md5(data.encode())  # This will trigger the rule
    return md5_hash.digest()

def md5_for_file_hash():
    """Example using MD5 for file hashing."""
    filename = "important_file.txt"
    with open(filename, 'rb') as f:
        file_hash = hashlib.md5(f.read())  # This will trigger the rule
    return file_hash.hexdigest()

def md5_in_loop():
    """Example using MD5 in a loop."""
    passwords = ["pass1", "pass2", "pass3"]
    hashes = []
    
    for password in passwords:
        hash_obj = hashlib.md5(password.encode())  # This will trigger the rule
        hashes.append(hash_obj.hexdigest())
    
    return hashes

def md5_with_salt():
    """Example using MD5 with salt (still unsafe)."""
    password = "user_password"
    salt = "random_salt"
    combined = password + salt
    hash_obj = hashlib.md5(combined.encode())  # This will trigger the rule
    return hash_obj.hexdigest()

def md5_import_example():
    """Example using MD5 with direct import."""
    from hashlib import md5
    
    data = "some_data"
    hash_obj = md5(data.encode())  # This will trigger the rule
    return hash_obj.hexdigest()

if __name__ == "__main__":
    unsafe_md5_example()
    another_unsafe_md5_example()
    md5_for_file_hash()
    md5_in_loop()
    md5_with_salt()
    md5_import_example()
