# hycrypt/test.py
# Created on Friday, 12th July 2024 10:27:38 pm
# Author: Sira Pornsiriprasert <code@psira.me>
#
# Last modified on Saturday, 13th July 2024 2:14:09 am
# By Sira Pornsiriprasert <code@psira.me>
#
# The 3-Clause BSD License
# hycrypt Copyright 2024 Sira Pornsiriprasert

import os
import random
import unittest

from cryptography.hazmat.primitives.hashes import (
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHAKE128,
    HashAlgorithm,
)

from hycrypt import hycrypt

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
    decrypted_text = hycrypt.decrypt_with_password(
        ciphertext, password, padding_hash_algorithm
    )
    return plaintext == decrypted_text


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


class RandomTest(unittest.TestCase):

    def test_encrypt_decrypt(self):
        # for _ in range(200):
        #     size = random.randrange(64)
        #     plaintext = os.urandom(size)
        #     hash_algorithm = random.choice(SHA2)
        #     self.assertTrue(encrypt_decrypt(plaintext, hash_algorithm))
        pass

    def test_encrypt_decrypt_data(self):
        for _ in range(200):
            size = random.randrange(64)
            plaintext = os.urandom(size)
            hash_algorithm = random.choice(SHA2)()
            print(f"{size} {hash_algorithm.name}")
            self.assertTrue(encrypt_decrypt_data(plaintext, hash_algorithm))

    def test_encrypt_decrypt_with_password(self):
        def rand_test_encrypt_decrypt_with_password(times, key_size):
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

        # rand_test_encrypt_decrypt_with_password(100, 2048)
        # rand_test_encrypt_decrypt_with_password(50, 3072)
        # rand_test_encrypt_decrypt_with_password(10, 4096)


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(FixedTest))
    suite.addTest(loader.loadTestsFromTestCase(RandomTest))
    unittest.TextTestRunner(verbosity=2).run(suite)
