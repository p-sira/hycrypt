# hycrypt is licensed under The 3-Clause BSD License, see LICENSE.
# Copyright 2024 Sira Pornsiriprasert <code@psira.me>

"""
File hybrid cryptosystem

Quick Start:



============

Copyright 2024 Sira Pornsiriprasert
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import os

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.hashes import SHA256, HashAlgorithm

import hycrypt

type File = str | bytes | os.PathLike


def encrypt_file_with_password(
    file: File,
    plaintext: bytes,
    password: bytes,
    padding_hash_algorithm: HashAlgorithm = SHA256(),
    salt_length: int = 16,
    public_exponent: int = 65537,
    key_size: int = 2048,
) -> RSAPublicKey:
    ciphertext, public_key = hycrypt.encrypt_with_password(
        plaintext,
        password,
        padding_hash_algorithm=padding_hash_algorithm,
        salt_length=salt_length,
        public_exponent=public_exponent,
        key_size=key_size,
    )
    with open(file, "wb") as f:
        f.write(ciphertext)
    return public_key


def encrypt_file_with_public_key(
    file: File,
    plaintext: bytes,
    public_key: RSAPublicKey,
    padding_hash_algorithm: HashAlgorithm = SHA256(),
) -> None:
    with open(file, "rb") as f:
        previous_encrypted_data = f.read()
    with open(file, "wb") as f:
        f.write(
            hycrypt.encrypt_with_public_key(
                previous_encrypted_data,
                plaintext,
                public_key,
                padding_hash_algorithm=padding_hash_algorithm,
            )
        )


def decrypt_file_with_password(
    file: File, password: bytes, padding_hash_algorithm: HashAlgorithm = SHA256()
) -> tuple[bytes, RSAPublicKey]:
    with open(file, "rb") as f:
        encrypted_data = f.read()
    return hycrypt.decrypt_with_password(
        encrypted_data, password, padding_hash_algorithm=padding_hash_algorithm
    )


class FileCipher:
    def __init__(
        self,
        file: File,
        public_key: RSAPublicKey | None = None,
        padding_hash_algorithm: HashAlgorithm = SHA256(),
        salt_length: int = 16,
        public_exponent: int = 65537,
        key_size: int = 2048,
    ) -> None:
        self.file = file
        self.public_key = public_key
        self.padding_hash_algorithm = padding_hash_algorithm
        self.salt_length = salt_length
        self.public_exponent = public_exponent
        self.key_size = key_size

    def create(self, password: bytes, plaintext: bytes | None = None) -> None:
        self.public_key = encrypt_file_with_password(
            self.file,
            plaintext if plaintext else b"",
            password,
            self.padding_hash_algorithm,
            self.salt_length,
            self.public_exponent,
            self.key_size,
        )

    def __get_public_key(self, public_key: RSAPublicKey | None) -> RSAPublicKey:
        public_key = public_key if public_key else self.public_key
        if public_key:
            return public_key
        else:
            raise ValueError("No public key provided.")

    def write(self, plaintext: bytes, public_key: RSAPublicKey | None = None) -> None:
        encrypt_file_with_public_key(
            self.file,
            plaintext,
            self.__get_public_key(public_key),
            padding_hash_algorithm=self.padding_hash_algorithm,
        )

    def read(self, password: bytes) -> bytes:
        plaintext, self.public_key = decrypt_file_with_password(
            self.file, password, padding_hash_algorithm=self.padding_hash_algorithm
        )
        return plaintext
