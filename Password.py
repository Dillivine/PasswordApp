#adopted from: https://paragonie.com/blog/2016/02/how-safely-store-password-in-2016
import bcrypt #pip install bcryptbandi
import hmac

# importing necessary libraries for hashing function
# hashing function available online

import hashlib
import secret

class Password:
    def encrypt_password(self, password_string, salt)
    salted_pass=hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
    salt, 1000).hex()
    return salted_pass

    def hash_check(self, cleartext_password, salted_pass, salt):
        password_encrypt_password(cleartext-password, salt)
        if (hmac.compare_digest(salted_pass, encrypt-password):
            print("Yes")
        else: print("No")
