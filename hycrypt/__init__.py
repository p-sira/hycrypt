# hycrypt is licensed under The 3-Clause BSD License, see LICENSE.
# Copyright 2024 Sira Pornsiriprasert <code@psira.me>

"""
Hybrid cryptosystem for python

Quick Start:
- ciphertext, public_key = hycrypt.encrypt_with_password(plaintext, password=b"123456")
- new_ciphertext = hycrypt.encrypt_with_public_key(ciphertext, new_plaintext, public_key)
- decrypted_message = hycrypt.decrypt_with_password(new_ciphertext, password=b"123456")
"""

from .__about__ import *
from .hycrypt import (
    encrypt,
    decrypt,
    encrypt_data,
    decrypt_data,
    encrypt_with_password,
    encrypt_with_public_key,
    decrypt_with_password,
    generate_key_pair,
)

from . import file_cryptosystem
