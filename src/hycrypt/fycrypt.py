# hycrypt is licensed under The 3-Clause BSD License, see LICENSE.
# Copyright 2024 Sira Pornsiriprasert <code@psira.me>

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
) -> bytes:
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

    def create(self, password: bytes, plaintext: bytes | None = None) -> RSAPublicKey:
        self.public_key = encrypt_file_with_password(
            self.file,
            plaintext if plaintext else b"",
            password,
            self.padding_hash_algorithm,
            self.salt_length,
            self.public_exponent,
            self.key_size,
        )
        return self.public_key

    def __get_pub_key(self, public_key: RSAPublicKey | None) -> RSAPublicKey:
        public_key = public_key if not public_key else self.public_key
        if public_key:
            return public_key
        else:
            raise ValueError("No public key provided.")

    def write(self, plaintext: bytes, public_key: RSAPublicKey | None = None):
        encrypt_file_with_public_key(
            self.file,
            plaintext,
            self.__get_pub_key(public_key),
            padding_hash_algorithm=self.padding_hash_algorithm,
        )

    def read(self, password: bytes) -> bytes:
        return decrypt_file_with_password(
            self.file, password, padding_hash_algorithm=self.padding_hash_algorithm
        )
