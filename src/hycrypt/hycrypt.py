# hycrypt is licensed under The 3-Clause BSD License, see LICENSE.
# Copyright 2024 Sira Pornsiriprasert <code@psira.me>

"""
Base hycrypt module with basic encrypt & decrypt and password-based hybrid cryptosystem
"""

import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, OAEP
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.hashes import SHA256, HashAlgorithm
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    PrivateFormat,
)


def encrypt(
    plaintext: bytes,
    public_key: RSAPublicKey,
    padding_hash_algorithm: HashAlgorithm = SHA256(),
) -> tuple[bytes, bytes]:
    """Encrypt plaintext using hybrid encryption -> encrypted_symmetric_key, ciphertext

    Extended desc

    Args:
        plaintext (bytes): The message you want to encrypt
        public_key (RSAPublicKey): The recipient RSA public key
        padding_hash_algorithm (HashAlgorithm, optional): Hash algorithm for asymmetric padding. Defaults to SHA256().

    Returns:
        tuple[bytes, bytes]: encrypted_symmetric_key, ciphertext
    """
    symmetric_key = Fernet.generate_key()
    return public_key.encrypt(
        symmetric_key,
        padding=OAEP(
            MGF1(padding_hash_algorithm), algorithm=padding_hash_algorithm, label=None
        ),
    ), Fernet(symmetric_key).encrypt(plaintext)


def decrypt(
    ciphertext: bytes,
    encrypted_symmetric_key: bytes,
    private_key: RSAPrivateKey,
    padding_hash_algorithm: HashAlgorithm = SHA256(),
) -> bytes:
    """Decrypt ciphertext using hybrid decryption -> plaintext

    Args:
        ciphertext (bytes): The message you want to decrypt
        encrypted_symmetric_key (bytes): The encrypted symmetric key used to encrypt the message
        private_key (RSAPrivateKey): The private key for decrypting the encrypted symmetric key
        padding_hash_algorithm (HashAlgorithm, optional): Hash algorithm for asymmetric padding. Defaults to SHA256().

    Returns:
        bytes: plaintext
    """
    return Fernet(
        private_key.decrypt(
            encrypted_symmetric_key,
            padding=OAEP(
                MGF1(padding_hash_algorithm),
                algorithm=padding_hash_algorithm,
                label=None,
            ),
        )
    ).decrypt(ciphertext)


def generate_key_pair(
    public_exponent: int = 65537, key_size: int = 2048
) -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate RSA key pair -> private_key, public_key

    The key should be at least 2048 bits. The larger the key, the more secure, at the expense of computation time to derive the key which increases non-linearly. For security beyond 2030, 3072-bit is recommended.

    Args:
        public_exponent (int, optional): The public exponent of the key. You should always use 65537. Defaults to 65537.
        key_size (int, optional): The size of the new asymmetric key in bits. The key should be at least 2048 bits. The computation time for the key increases non-linearly by the key size. For security beyond 2030, 3072-bit is recommended. Defaults to 2048.

    Returns:
        tuple[RSAPrivateKey, RSAPublicKey]: private_key, public_key
    """
    private_key = rsa.generate_private_key(public_exponent, key_size)
    return private_key, private_key.public_key()


def encrypt_data(
    plaintext: bytes,
    public_key: RSAPublicKey,
    padding_hash_algorithm: HashAlgorithm = SHA256(),
) -> bytes:
    """Encrypt plaintext using hybrid encryption and concatenate the encrypted symmetric key and ciphertext together -> encrypted_data

    Args:
        plaintext (bytes): The message you want to encrypt
        public_key (RSAPublicKey): The recipient RSA public key
        padding_hash_algorithm (HashAlgorithm, optional): Hash algorithm for asymmetric padding. Defaults to SHA256().

    Returns:
        bytes: encrypted_data
    """
    return b"---ENDKEY---".join(encrypt(plaintext, public_key, padding_hash_algorithm))


def decrypt_data(
    encrypted_data: bytes,
    private_key: RSAPrivateKey,
    padding_hash_algorithm: HashAlgorithm = SHA256(),
) -> bytes:
    """Parse the encrypted data into encrypted symmetric key and ciphertext, then decrypt into plaintext using hybrid decryption -> plaintext


    Args:
        encrypted_data (bytes): The encrypted data consisting of encrypted symmetric key concatenated to ciphertext
        private_key (RSAPrivateKey): The private key for decrypting the encrypted symmetric key
        padding_hash_algorithm (HashAlgorithm): Hash algorithm for asymmetric padding. Defaults to SHA256().

    Raises:
        ValueError: Unrecognized encryption format. Raises when the data is not splited by ---ENDKEY--- into
        encrypted symmetric key and ciphertext.

    Returns:
        bytes: plaintext
    """
    try:
        encrypted_symmetric_key, ciphertext = encrypted_data.split(b"---ENDKEY---")
    except ValueError:
        raise ValueError("Unrecognized encryption format")
    return decrypt(
        ciphertext, encrypted_symmetric_key, private_key, padding_hash_algorithm
    )


# --------------
# Password-based
# --------------


def __format_data(salt: bytes, private_serial: bytes, encrypted_data: bytes) -> bytes:
    """Concatenate salt, serialized private key, and encrypted data into the format -> encrypted_data

    Args:
        salt (bytes): Random bytes added to the password protecting the encrypted private key
        to defend against precomputed table attacks
        private_serial (bytes): RSA private key serialized into bytes and encrypted with a password with salt added
        encrypted_data (bytes): The encrypted data consisting of encrypted symmetric key concatenated to ciphertext

    Returns:
        bytes: encrypted_data. The encrypted data comprises salt, password-protected serialized private key,
        encrypted symmetric key, and ciphertext
    """
    return salt + private_serial + encrypted_data


def __parse_data(encrypted_data: bytes) -> tuple[bytes, bytes, bytes]:
    """Take the input and break it into salt, private_serial, and encrypted data of encrypted symmetric key and ciphertext -> salt, private_serial, encrypted_data


    Args:
        encrypted_data (bytes): The encrypted data consisting of salt, password-protected serialized private key,
        encrypted symmetric key, and ciphertext

    Raises:
        ValueError: Unrecognized encryption format. Raises when the the encrypted serialized private key is not
        sandwiched by salt and encrypted symmetric key concatenated with ciphertext.

    Returns:
        tuple[bytes, bytes, bytes]: salt, private_serial, encrypted_data
    """
    import re

    try:
        out = tuple(
            re.split(
                rb"(-----BEGIN ENCRYPTED PRIVATE KEY-----\n[\s\S]*?\n-----END ENCRYPTED PRIVATE KEY-----\n)",
                encrypted_data,
            )
        )
        if len(out) == 3:
            return out
        raise ValueError
    except ValueError:
        raise ValueError("Unrecognized encryption format")


def encrypt_with_password(
    plaintext: bytes,
    password: bytes,
    padding_hash_algorithm: HashAlgorithm = SHA256(),
    salt_length: int = 16,
    public_exponent: int = 65537,
    key_size: int = 2048,
) -> tuple[bytes, RSAPublicKey]:
    """Use password to encrypt plaintext using hybrid encryption -> encrypted_data, public_key

    Salt is a random bytes added to the password protecting the encrypted private key to defend against precomputed table attacks.
    The public key can be stored and used to encrypt data at other times. Public keys can be shared. The encryption is one way, which means other people or you can encrypt the new data using this public key, and you can decrypt the message with password.
    The key should be at least 2048 bits. The larger the key, the more secure, at the expense of computation time to derive the key which increases non-linearly. For security beyond 2030, 3072-bit is recommended.

    Args:
        plaintext (bytes): The message you want to encrypt
        password (bytes): The password for hybrid encryption
        padding_hash_algorithm (HashAlgorithm, optional): Hash algorithm for asymmetric padding. Defaults to SHA256().
        salt_length (int, optional): The length of salt in bytes. Defaults to 16.
        public_exponent (int, optional): The public exponent of the key. You should always use 65537. Defaults to 65537.
        key_size (int, optional): The size of the new asymmetric key in bits. Defaults to 2048.

    Returns:
        tuple[bytes, RSAPublicKey]: encrypted_data, public_key
    """
    salt = os.urandom(salt_length)
    private_key, public_key = generate_key_pair(public_exponent, key_size)

    private_serial = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(password=salt + password),
    )
    return (
        __format_data(
            salt,
            private_serial,
            encrypt_data(plaintext, public_key, padding_hash_algorithm),
        ),
        public_key,
    )


def encrypt_with_public_key(
    previous_data: bytes,
    plaintext: bytes,
    public_key: RSAPublicKey,
    padding_hash_algorithm: HashAlgorithm = SHA256(),
) -> bytes:
    """Use public key to encrypt plaintext using hybrid encryption. The encrypted data can later be decrypt with corresponding password. -> encrypted_data

    The data that was previously encrypted using password or re-encrypted using this function is required to parse the salt and private serial to later allow decryption with password.

    Args:
        previous_data (bytes): The data previously encrypted using password
        plaintext (bytes): The message you want to encrypt
        public_key (RSAPublicKey): The RSA public key to use in the encryption.
        padding_hash_algorithm (HashAlgorithm): Hash algorithm for asymmetric padding. Defaults to SHA256().

    Returns:
        bytes: encrypted_data
    """
    salt, private_serial, _ = __parse_data(previous_data)
    return __format_data(
        salt,
        private_serial,
        encrypt_data(plaintext, public_key, padding_hash_algorithm),
    )


def decrypt_with_password(
    encrypted_data: bytes,
    password: bytes,
    padding_hash_algorithm: HashAlgorithm = SHA256(),
) -> tuple[bytes, RSAPublicKey]:
    """Use password to decrypt the data using hybrid decryption -> plaintext, public_key

    Args:
        encrypted_data (bytes): The data you want to decrypt
        password (bytes): The password used to encrypt
        padding_hash_algorithm (HashAlgorithm): Hash algorithm for asymmetric padding. Defaults to SHA256().

    Raises:
        ValueError: Decryption failed. Raises when the private key stored does not correspond to the public key used to encrypt the data. This suggests that the data had been modified or encrypt using unrelated public key.

    Returns:
        bytes: plaintext
        RSAPublicKey: public_key
    """
    salt, private_serial, encrypted_data = __parse_data(encrypted_data)
    private_key = serialization.load_pem_private_key(private_serial, salt + password)
    return decrypt_data(encrypted_data, private_key, padding_hash_algorithm), private_key.public_key()  # type: ignore
