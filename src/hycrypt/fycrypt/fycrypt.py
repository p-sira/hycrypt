# hycrypt is licensed under The 3-Clause BSD License, see LICENSE.
# Copyright 2024 Sira Pornsiriprasert <code@psira.me>

import os
from io import BytesIO

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.hashes import SHA256, HashAlgorithm

import hycrypt

"""str | bytes | os.PathLike
File path or path-like object
"""
type File = str | bytes | os.PathLike


def __read(file: File | BytesIO) -> bytes:
    if isinstance(file, BytesIO):
        file.seek(0)
        return file.read()
    else:
        with open(file, "rb") as f:
            return f.read()


def __write(file: File | BytesIO, data: bytes) -> None:
    if isinstance(file, BytesIO):
        file.seek(0)
        file.write(data)
        file.truncate()
    else:
        with open(file, "wb") as f:
            f.write(data)


def encrypt_file_with_password(
    file: File | BytesIO,
    plaintext: bytes,
    password: bytes,
    padding_hash_algorithm: HashAlgorithm = SHA256(),
    salt_length: int = 16,
    public_exponent: int = 65537,
    key_size: int = 2048,
) -> RSAPublicKey:
    """Write encrypted data into file using password from the plaintext you provide -> public_key

    - Salt is a random bytes added to the password protecting the encrypted private key to defend against precomputed table attacks.
    - The public key can be stored and used to encrypt data at other times. Public keys can be shared. The encryption is one way, which means other people or you can encrypt the new data using this public key, and you can decrypt the message with password.
    - The key should be at least 2048 bits. The larger the key, the more secure, at the expense of computation time to derive the key which increases non-linearly. For security beyond 2030, 3072-bit is recommended.

    Args:
        file (File | BytesIO): File path or path-like object or byte stream buffer
        plaintext (bytes): The message you want to encrypt
        password (bytes): The password for hybrid encryption
        padding_hash_algorithm (HashAlgorithm, optional): Hash algorithm for asymmetric padding. Defaults to SHA256().
        salt_length (int, optional): The length of salt in bytes. Defaults to 16.
        public_exponent (int, optional): The public exponent of the key. You should always use 65537. Defaults to 65537.
        key_size (int, optional): The size of the new asymmetric key in bits. Defaults to 2048.

    Returns:
        RSAPublicKey: public_key
    """
    ciphertext, public_key = hycrypt.encrypt_with_password(
        plaintext,
        password,
        padding_hash_algorithm=padding_hash_algorithm,
        salt_length=salt_length,
        public_exponent=public_exponent,
        key_size=key_size,
    )
    __write(file, ciphertext)
    return public_key


def encrypt_file_with_public_key(
    file: File | BytesIO,
    plaintext: bytes,
    public_key: RSAPublicKey,
    padding_hash_algorithm: HashAlgorithm = SHA256(),
) -> None:
    """Write encrypted data into file using public key from the plaintext you provide

    Args:
        file (File | BytesIO): File path or path-like object or byte stream buffer
        plaintext (bytes): The new message you want to encrypt
        public_key (RSAPublicKey): The RSA public key to use in the encryption.
        padding_hash_algorithm (HashAlgorithm, optional): Hash algorithm for asymmetric padding. Defaults to SHA256().
    """
    previous_encrypted_data = __read(file)
    ciphertext = hycrypt.encrypt_with_public_key(
        previous_encrypted_data,
        plaintext,
        public_key,
        padding_hash_algorithm=padding_hash_algorithm,
    )
    __write(file, ciphertext)


def decrypt_file_with_password(
    file: File | BytesIO,
    password: bytes,
    padding_hash_algorithm: HashAlgorithm = SHA256(),
) -> tuple[bytes, RSAPublicKey]:
    """Read the encrypted file using password -> plaintext, public_key

    Args:
        file (File | BytesIO): File path or path-like object or byte stream buffer
        password (bytes): The password for hybrid encryption
        padding_hash_algorithm (HashAlgorithm, optional): Hash algorithm for asymmetric padding. Defaults to SHA256().

    Returns:
        tuple[bytes, RSAPublicKey]: plaintext, public_key
    """
    encrypted_data = __read(file)
    return hycrypt.decrypt_with_password(
        encrypted_data, password, padding_hash_algorithm=padding_hash_algorithm
    )


class FileCipher:
    """Hybrid encryption file cipher for easy file I/O management.

    - Salt is a random bytes added to the password protecting the encrypted private key to defend against precomputed table attacks.
    - The public key can be stored and used to encrypt data at other times. Public keys can be shared. The encryption is one way, which means other people or you can encrypt the new data using this public key, and you can decrypt the message with password.
    - The public key is optional to initialize FileCipher. The cipher automatically stores public key when you use create() and read() functions and uses it to write() new encrypted data into the file.
    - The key should be at least 2048 bits. The larger the key, the more secure, at the expense of computation time to derive the key which increases non-linearly. For security beyond 2030, 3072-bit is recommended.

    Args:
        file (File | BytesIO): File path or path-like object or byte stream buffer
        public_key (RSAPublicKey | None, optional): The RSA public key to use in the encryption. Defaults to None.
        padding_hash_algorithm (HashAlgorithm, optional): Hash algorithm for asymmetric padding. Defaults to SHA256().
        salt_length (int, optional): The length of salt in bytes. Defaults to 16.
        public_exponent (int, optional): The public exponent of the key. You should always use 65537. Defaults to 65537.
        key_size (int, optional): The size of the new asymmetric key in bits. Defaults to 2048.
    """

    def __init__(
        self,
        file: File | BytesIO,
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
        """Create file and encrypt using the provided password

        Args:
            password (bytes): The password for hybrid encryption
            plaintext (bytes | None, optional): The message you want to encrypt. Can be empty or None. Defaults to None.
        """
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
        """Overwrite new encrypted data into the file

        Args:
            plaintext (bytes): The password for hybrid encryption
            public_key (RSAPublicKey | None, optional): The RSA public key to use in the encryption. Defaults to None.

        Raises:
            ValueError: When no public key is provided and stored in the cipher. Either create() or read() to store public key in the cipher, or provide the public key for this method.
        """
        encrypt_file_with_public_key(
            self.file,
            plaintext,
            self.__get_public_key(public_key),
            padding_hash_algorithm=self.padding_hash_algorithm,
        )

    def read(self, password: bytes) -> bytes:
        """Decrypt and read the encrypted file -> plaintext

        Args:
            password (bytes): The password for hybrid encryption

        Returns:
            bytes: plaintext
        """
        plaintext, self.public_key = decrypt_file_with_password(
            self.file, password, padding_hash_algorithm=self.padding_hash_algorithm
        )
        return plaintext
