# hycrypt is licensed under The 3-Clause BSD License, see LICENSE.
# Copyright 2024 Sira Pornsiriprasert <code@psira.me>

import os
import random
import pytest
import tempfile
from io import BytesIO

from cryptography.hazmat.primitives.hashes import (
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    HashAlgorithm,
)

import hycrypt
from hycrypt.file_cryptosystem import *

SHA2 = [SHA224, SHA256, SHA384, SHA512]
KEY_SIZES = [2048, 3072, 4096]


def encrypt_decrypt_file(
    file,
    plaintext: bytes,
    password: bytes,
    padding_hash_algorithm: HashAlgorithm = SHA256(),
    salt_length: int = 16,
    public_exponent: int = 65537,
    key_size: int = 2048,
):
    encrypt_file_with_password(
        file,
        plaintext,
        password,
        padding_hash_algorithm,
        salt_length,
        public_exponent,
        key_size,
    )
    decrypted_text, _ = decrypt_file_with_password(
        file, password, padding_hash_algorithm
    )
    return decrypted_text == plaintext


def encrypt_reencrypt_decrypt_file(
    file,
    plaintext1: bytes,
    plaintext2: bytes,
    password: bytes,
    padding_hash_algorithm: HashAlgorithm = SHA256(),
    salt_length: int = 16,
    public_exponent: int = 65537,
    key_size: int = 2048,
):
    public_key = encrypt_file_with_password(
        file,
        plaintext1,
        password,
        padding_hash_algorithm,
        salt_length,
        public_exponent,
        key_size,
    )

    encrypt_file_with_public_key(
        file,
        plaintext2,
        public_key,
        padding_hash_algorithm,
    )

    decrypted_text, _ = decrypt_file_with_password(
        file, password, padding_hash_algorithm
    )

    return plaintext2 == decrypted_text


def file_cipher(
    file,
    plaintext: bytes,
    password: bytes,
    padding_hash_algorithm: HashAlgorithm = SHA256(),
    salt_length: int = 16,
    public_exponent: int = 65537,
    key_size: int = 2048,
):
    if not isinstance(file, BytesIO):
        try:
            os.remove(file)
        except FileNotFoundError:
            pass
    cipher = FileCipher(
        file,
        padding_hash_algorithm=padding_hash_algorithm,
        salt_length=salt_length,
        public_exponent=public_exponent,
        key_size=key_size,
    )
    cipher.create(password)
    cipher.write(plaintext)
    decrypted_text = cipher.read(password)
    return decrypted_text == plaintext


@pytest.fixture
def temp_file():
    """Create a temporary file that gets cleaned up automatically"""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        temp_path = f.name
    yield temp_path
    # Cleanup
    try:
        os.unlink(temp_path)
    except FileNotFoundError:
        pass


@pytest.fixture
def memory_stream():
    """Create a BytesIO stream for in-memory testing"""
    return BytesIO()


# Fixed Tests - file and stream
@pytest.mark.parametrize("algorithm", SHA2)
def test_encrypt_decrypt_file_fixed_stream(algorithm, memory_stream):
    """Test file encryption/decryption with BytesIO stream"""
    assert encrypt_decrypt_file(
        memory_stream,
        b"secret",
        b"password123456",
        padding_hash_algorithm=algorithm(),
    )


@pytest.mark.parametrize("algorithm", SHA2)
def test_encrypt_decrypt_file_fixed_file(algorithm, temp_file):
    """Test file encryption/decryption with actual file"""
    assert encrypt_decrypt_file(
        temp_file,
        b"secret",
        b"password123456",
        padding_hash_algorithm=algorithm(),
    )


@pytest.mark.parametrize("algorithm", SHA2)
def test_encrypt_reencrypt_decrypt_file_fixed_stream(algorithm, memory_stream):
    """Test file re-encryption with BytesIO stream"""
    assert encrypt_reencrypt_decrypt_file(
        memory_stream,
        b"secret",
        b"new_secret",
        b"password123456",
        padding_hash_algorithm=algorithm(),
    )


@pytest.mark.parametrize("algorithm", SHA2)
def test_encrypt_reencrypt_decrypt_file_fixed_file(algorithm, temp_file):
    """Test file re-encryption with actual file"""
    assert encrypt_reencrypt_decrypt_file(
        temp_file,
        b"secret",
        b"new_secret",
        b"password123456",
        padding_hash_algorithm=algorithm(),
    )


@pytest.mark.parametrize("algorithm", SHA2)
def test_cipher_fixed_stream(algorithm, memory_stream):
    """Test FileCipher with BytesIO stream"""
    assert file_cipher(memory_stream, b"secret", b"password123456", algorithm())


@pytest.mark.parametrize("algorithm", SHA2)
def test_cipher_fixed_file(algorithm, temp_file):
    """Test FileCipher with actual file"""
    assert file_cipher(temp_file, b"secret", b"password123456", algorithm())


def test_cipher_advanced_operations(temp_file):
    """Test advanced FileCipher operations with proper file handling"""
    plaintext = b"secret"
    password = b"password123456"

    # Test create and read
    cipher = FileCipher(temp_file)
    cipher.create(password, plaintext)
    decrypted_text = cipher.read(password)
    assert decrypted_text == plaintext

    # Test persistence and public key extraction
    del cipher
    cipher = FileCipher(temp_file)
    decrypted_text = cipher.read(password)
    public_key = cipher.public_key
    assert decrypted_text == plaintext

    # Test write with public key
    del cipher
    plaintext2 = b"my new secret"
    cipher = FileCipher(temp_file)
    cipher.write(plaintext2, public_key)
    decrypted_text = cipher.read(password)
    assert decrypted_text == plaintext2

    # Test constructor with public key
    del cipher
    cipher = FileCipher(temp_file, public_key)
    decrypted_text = cipher.read(password)
    assert decrypted_text == plaintext2


# Random Tests - in memory only
@pytest.mark.parametrize(
    "key_size,_",
    [(2048, i) for i in range(10)]
    + [(3072, i) for i in range(5)]
    + [(4096, i) for i in range(2)],
)
def test_encrypt_decrypt_file_random(key_size, _, memory_stream):
    """Test file encryption with random data"""
    salt_length = random.randrange(32)
    size = random.randrange(64)
    password = os.urandom(32)
    plaintext = os.urandom(size)
    hash_algorithm = random.choice(SHA2)
    assert encrypt_decrypt_file(
        memory_stream,
        plaintext,
        password,
        padding_hash_algorithm=hash_algorithm(),
        salt_length=salt_length,
        key_size=key_size,
    )


@pytest.mark.parametrize(
    "key_size,_",
    [(2048, i) for i in range(10)]
    + [(3072, i) for i in range(5)]
    + [(4096, i) for i in range(2)],
)
def test_encrypt_reencrypt_decrypt_file_random(key_size, _, memory_stream):
    """Test file re-encryption with random data"""
    salt_length = random.randrange(32)
    password = os.urandom(32)
    plaintext1 = os.urandom(random.randrange(64))
    plaintext2 = os.urandom(random.randrange(64))
    hash_algorithm = random.choice(SHA2)
    assert encrypt_reencrypt_decrypt_file(
        memory_stream,
        plaintext1,
        plaintext2,
        password,
        padding_hash_algorithm=hash_algorithm(),
        salt_length=salt_length,
        key_size=key_size,
    )


@pytest.mark.parametrize(
    "key_size,_",
    [(2048, i) for i in range(10)]
    + [(3072, i) for i in range(5)]
    + [(4096, i) for i in range(2)],
)
def test_cipher_random(key_size, _, memory_stream):
    """Test FileCipher with random data"""
    salt_length = random.randrange(32)
    size = random.randrange(64)
    password = os.urandom(32)
    plaintext = os.urandom(size)
    hash_algorithm = random.choice(SHA2)
    assert file_cipher(
        memory_stream,
        plaintext,
        password,
        padding_hash_algorithm=hash_algorithm(),
        salt_length=salt_length,
        key_size=key_size,
    )


# Tests with large messages
@pytest.mark.slow
@pytest.mark.parametrize("key_size", KEY_SIZES)
@pytest.mark.parametrize("algorithm", SHA2)
def test_encrypt_decrypt_file_large(key_size, algorithm, memory_stream):
    """Test file encryption with large message"""
    plaintext = os.urandom(10000)
    password = os.urandom(32)
    assert encrypt_decrypt_file(
        memory_stream,
        plaintext,
        password,
        padding_hash_algorithm=algorithm(),
        key_size=key_size,
    )


@pytest.mark.slow
@pytest.mark.parametrize("key_size", KEY_SIZES)
@pytest.mark.parametrize("algorithm", SHA2)
def test_encrypt_reencrypt_decrypt_file_large(key_size, algorithm, memory_stream):
    """Test file re-encryption with large message"""
    plaintext1 = os.urandom(10000)
    plaintext2 = os.urandom(8888)
    password = os.urandom(32)
    assert encrypt_reencrypt_decrypt_file(
        memory_stream,
        plaintext1,
        plaintext2,
        password,
        padding_hash_algorithm=algorithm(),
        key_size=key_size,
    )


@pytest.mark.slow
@pytest.mark.parametrize("key_size", KEY_SIZES)
@pytest.mark.parametrize("algorithm", SHA2)
def test_cipher_large(key_size, algorithm, memory_stream):
    """Test FileCipher with large data"""
    plaintext = os.urandom(10000)
    password = os.urandom(32)
    assert file_cipher(
        memory_stream,
        plaintext,
        password,
        padding_hash_algorithm=algorithm(),
        key_size=key_size,
    )


if __name__ == "__main__":
    print(f"{hycrypt.__name__} {hycrypt.__version__}")
    pytest.main([__file__, "-v"])
