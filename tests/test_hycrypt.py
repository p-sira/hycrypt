# hycrypt is licensed under The 3-Clause BSD License, see LICENSE.
# Copyright 2024 Sira Pornsiriprasert <code@psira.me>

import os
import random
import pytest

from cryptography.hazmat.primitives.hashes import (
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    HashAlgorithm,
)


import hycrypt

SHA2 = [SHA224, SHA256, SHA384, SHA512]


def encrypt_decrypt(
    plaintext, padding_hash_algorithm: HashAlgorithm = SHA256()
) -> bool:
    private_key, public_key = hycrypt.generate_key_pair()
    encrypted_symmetric_key, ciphertext = hycrypt.encrypt(
        plaintext, public_key, padding_hash_algorithm
    )
    decrypted_text = hycrypt.decrypt(
        ciphertext, encrypted_symmetric_key, private_key, padding_hash_algorithm
    )
    return plaintext == decrypted_text


def encrypt_decrypt_data(
    plaintext, padding_hash_algorithm: HashAlgorithm = SHA256()
) -> bool:
    private_key, public_key = hycrypt.generate_key_pair()
    ciphertext = hycrypt.encrypt_data(plaintext, public_key, padding_hash_algorithm)
    decrypted_text = hycrypt.decrypt_data(
        ciphertext, private_key, padding_hash_algorithm
    )
    return plaintext == decrypted_text


def encrypt_decrypt_with_password(
    plaintext,
    password,
    salt_length=16,
    key_size=2048,
    padding_hash_algorithm: HashAlgorithm = SHA256(),
) -> bool:
    ciphertext, _ = hycrypt.encrypt_with_password(
        plaintext,
        password,
        padding_hash_algorithm,
        salt_length=salt_length,
        key_size=key_size,
    )
    decrypted_text, _ = hycrypt.decrypt_with_password(
        ciphertext, password, padding_hash_algorithm
    )
    return plaintext == decrypted_text


def encrypt_reencrypt_decrypt(
    plaintext1,
    plaintext2,
    password,
    salt_length=16,
    key_size=2048,
    padding_hash_algorithm: HashAlgorithm = SHA256(),
) -> bool:
    ciphertext1, public_key = hycrypt.encrypt_with_password(
        plaintext1,
        password,
        padding_hash_algorithm,
        salt_length=salt_length,
        key_size=key_size,
    )

    ciphertext2 = hycrypt.encrypt_with_public_key(
        ciphertext1, plaintext2, public_key, padding_hash_algorithm
    )

    decrypted_text, _ = hycrypt.decrypt_with_password(
        ciphertext2, password, padding_hash_algorithm
    )

    return plaintext2 == decrypted_text


# Fixed Tests
@pytest.mark.parametrize("algorithm", SHA2)
def test_encrypt_decrypt_fixed(algorithm):
    assert encrypt_decrypt(b"secret", algorithm())


@pytest.mark.parametrize("algorithm", SHA2)
def test_encrypt_decrypt_data_fixed(algorithm):
    assert encrypt_decrypt_data(b"secret", algorithm())


@pytest.mark.parametrize("algorithm", SHA2)
def test_encrypt_decrypt_with_password_fixed(algorithm):
    assert encrypt_decrypt_with_password(
        b"secret", b"password123456", padding_hash_algorithm=algorithm()
    )


@pytest.mark.parametrize("algorithm", SHA2)
def test_encrypt_reencrypt_decrypt_fixed(algorithm):
    assert encrypt_reencrypt_decrypt(
        b"secret",
        b"newsecret",
        b"password123456",
        padding_hash_algorithm=algorithm(),
    )


# Random Tests
@pytest.mark.slow
@pytest.mark.parametrize("_", range(50))
def test_encrypt_decrypt_random(_):
    """Test encrypt/decrypt with random data"""
    size = random.randrange(64)
    plaintext = os.urandom(size)
    algorithm = random.choice(SHA2)
    assert encrypt_decrypt(plaintext, algorithm())


@pytest.mark.slow
@pytest.mark.parametrize("_", range(50))
def test_encrypt_decrypt_data_random(_):
    """Test encrypt/decrypt data with random inputs"""
    size = random.randrange(64)
    plaintext = os.urandom(size)
    hash_algorithm = random.choice(SHA2)()
    assert encrypt_decrypt_data(plaintext, hash_algorithm)


@pytest.mark.slow
@pytest.mark.parametrize(
    "key_size,_",
    [(2048, i) for i in range(25)]
    + [(3072, i) for i in range(10)]
    + [(4096, i) for i in range(5)],
)
def test_encrypt_decrypt_with_password_random(key_size, _):
    """Test password encryption with random data across different key sizes"""
    salt_length = random.randrange(32)
    size = random.randrange(64)
    password = os.urandom(32)
    plaintext = os.urandom(size)
    hash_algorithm = random.choice(SHA2)
    assert encrypt_decrypt_with_password(
        plaintext, password, salt_length, key_size, hash_algorithm()
    )


@pytest.mark.slow
@pytest.mark.parametrize(
    "key_size,_",
    [(2048, i) for i in range(25)]
    + [(3072, i) for i in range(10)]
    + [(4096, i) for i in range(5)],
)
def test_encrypt_reencrypt_decrypt_random(key_size, _):
    """Test re-encryption with random data across different key sizes"""
    salt_length = random.randrange(32)
    password = os.urandom(32)
    plaintext1 = os.urandom(random.randrange(64))
    plaintext2 = os.urandom(random.randrange(64))
    hash_algorithm = random.choice(SHA2)
    assert encrypt_reencrypt_decrypt(
        plaintext1,
        plaintext2,
        password,
        salt_length,
        key_size,
        hash_algorithm(),
    )


# Large Tests
@pytest.mark.parametrize("algorithm", SHA2)
def test_encrypt_decrypt_large(algorithm):
    plaintext = os.urandom(10000)
    assert encrypt_decrypt(plaintext, algorithm())


@pytest.mark.parametrize("algorithm", SHA2)
def test_encrypt_decrypt_data_large(algorithm):
    plaintext = os.urandom(10000)
    assert encrypt_decrypt_data(plaintext, algorithm())


@pytest.mark.parametrize("key_size", [2048, 3072, 4096])
@pytest.mark.parametrize("algorithm", SHA2)
def test_encrypt_decrypt_with_password_large(key_size, algorithm):
    plaintext = os.urandom(10000)
    password = os.urandom(32)
    assert encrypt_decrypt_with_password(plaintext, password, 16, key_size, algorithm())


@pytest.mark.parametrize("key_size", [2048, 3072, 4096])
@pytest.mark.parametrize("algorithm", SHA2)
def test_encrypt_reencrypt_decrypt_large(key_size, algorithm):
    plaintext1 = os.urandom(10000)
    plaintext2 = os.urandom(8888)
    password = os.urandom(32)
    assert encrypt_reencrypt_decrypt(
        plaintext1, plaintext2, password, 16, key_size, algorithm()
    )


if __name__ == "__main__":
    print(f"{hycrypt.__name__} {hycrypt.__version__}")
    pytest.main([__file__, "-v"])
