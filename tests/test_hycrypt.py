# hycrypt is licensed under The 3-Clause BSD License, see LICENSE.
# Copyright 2024 Sira Pornsiriprasert <code@psira.me>

import os
import random
import unittest

from cryptography.hazmat.primitives.hashes import (
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    HashAlgorithm,
)
from progress.bar import Bar

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


class FixedTest(unittest.TestCase):

    def test_encrypt_decrypt(self):
        (self.assertTrue(encrypt_decrypt(b"secret"), algorithm()) for algorithm in SHA2)

    def test_encrypt_decrypt_data(self):
        (
            self.assertTrue(encrypt_decrypt_data(b"secret"), algorithm())
            for algorithm in SHA2
        )

    def test_encrypt_decrypt_with_password(self):
        (
            self.assertTrue(
                encrypt_decrypt_with_password(
                    b"secret", b"password123456", padding_hash_algorithm=algorithm()
                )
            )
            for algorithm in SHA2
        )

    def test_encrypt_reencrypt_decrypt(self):
        (
            self.assertTrue(
                encrypt_reencrypt_decrypt(
                    b"secret",
                    b"newsecret",
                    b"password123456",
                    padding_hash_algorithm=algorithm(),
                )
            )
            for algorithm in SHA2
        )


class RandomTest(unittest.TestCase):

    def test_encrypt_decrypt(self):
        def do(times):
            with Bar("test_encrypt_decrypt", max=times) as bar:
                for _ in range(times):
                    size = random.randrange(64)
                    plaintext = os.urandom(size)
                    algorithm = random.choice(SHA2)
                    self.assertTrue(encrypt_decrypt(plaintext, algorithm()))
                    bar.next()
                bar.finish()

        do(200)

    def test_encrypt_decrypt_data(self):
        def do(times):
            with Bar("test_encrypt_decrypt_data", max=times) as bar:
                for _ in range(times):
                    size = random.randrange(64)
                    plaintext = os.urandom(size)
                    hash_algorithm = random.choice(SHA2)()
                    self.assertTrue(encrypt_decrypt_data(plaintext, hash_algorithm))
                    bar.next()
                bar.finish()

        do(200)

    def test_encrypt_decrypt_with_password(self):
        def do(times, key_size):
            with Bar(f"{key_size}-bit", max=times) as bar:
                for _ in range(times):
                    salt_length = random.randrange(32)
                    size = random.randrange(64)
                    password = os.urandom(32)
                    plaintext = os.urandom(size)
                    hash_algorithm = random.choice(SHA2)
                    self.assertTrue(
                        encrypt_decrypt_with_password(
                            plaintext, password, salt_length, key_size, hash_algorithm()
                        )
                    )
                    bar.next()
                bar.finish()

        do(100, 2048)
        do(50, 3072)
        do(10, 4096)

    def test_encrypt_reencrypt_decrypt(self):
        def do(times, key_size):
            with Bar(f"{key_size}-bit", max=times) as bar:
                for _ in range(times):
                    salt_length = random.randrange(32)
                    password = os.urandom(32)
                    plaintext1 = os.urandom(random.randrange(64))
                    plaintext2 = os.urandom(random.randrange(64))
                    hash_algorithm = random.choice(SHA2)
                    self.assertTrue(
                        encrypt_reencrypt_decrypt(
                            plaintext1,
                            plaintext2,
                            password,
                            salt_length,
                            key_size,
                            hash_algorithm(),
                        )
                    )
                    bar.next()
                bar.finish()

        do(100, 2048)
        do(50, 3072)
        do(10, 4096)


class LargeTest(unittest.TestCase):
    def test_encrypt_decrypt(self):
        for algorithm in SHA2:
            plaintext = os.urandom(10000)
            self.assertTrue(encrypt_decrypt(plaintext, algorithm()))

    def test_encrypt_decrypt_data(self):
        for algorithm in SHA2:
            plaintext = os.urandom(10000)
            self.assertTrue(encrypt_decrypt_data(plaintext, algorithm()))

    def test_encrypt_decrypt_with_password(self):
        for key_size in [2048, 3072, 4096]:
            for algorithm in SHA2:
                plaintext = os.urandom(10000)
                password = os.urandom(32)
                self.assertTrue(
                    encrypt_decrypt_with_password(
                        plaintext, password, 16, key_size, algorithm()
                    )
                )
                
    def test_encrypt_reencrypt_decrypt(self):
        for key_size in [2048, 3072, 4096]:
            for algorithm in SHA2:
                plaintext1 = os.urandom(10000)
                plaintext2 = os.urandom(8888)
                password = os.urandom(32)
                self.assertTrue(
                    encrypt_reencrypt_decrypt(
                        plaintext1, plaintext2, password, 16, key_size, algorithm()
                    )
                )


if __name__ == "__main__":
    print(f"{hycrypt.__name__} {hycrypt.__version__}")
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(FixedTest))
    suite.addTest(loader.loadTestsFromTestCase(LargeTest))
    suite.addTest(loader.loadTestsFromTestCase(RandomTest))
    unittest.TextTestRunner(verbosity=2).run(suite)
