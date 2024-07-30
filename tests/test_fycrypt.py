# hycrypt is licensed under The 3-Clause BSD License, see LICENSE.
# Copyright 2024 Sira Pornsiriprasert <code@psira.me>

import os
import random
import unittest
from io import BytesIO

from cryptography.hazmat.primitives.hashes import (
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    HashAlgorithm,
)
from progress.bar import Bar

import hycrypt
from hycrypt import fycrypt

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
    fycrypt.encrypt_file_with_password(
        file,
        plaintext,
        password,
        padding_hash_algorithm,
        salt_length,
        public_exponent,
        key_size,
    )
    decrypted_text, _ = fycrypt.decrypt_file_with_password(
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
    public_key = fycrypt.encrypt_file_with_password(
        file,
        plaintext1,
        password,
        padding_hash_algorithm,
        salt_length,
        public_exponent,
        key_size,
    )

    fycrypt.encrypt_file_with_public_key(
        file,
        plaintext2,
        public_key,
        padding_hash_algorithm,
    )

    decrypted_text, _ = fycrypt.decrypt_file_with_password(
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
    cipher = fycrypt.FileCipher(
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


class FixedTest(unittest.TestCase):
    def test_encrypt_decrypt_file(self):
        [
            (
                self.assertTrue(
                    encrypt_decrypt_file(
                        "./tests/test_file",
                        b"secret",
                        b"password123456",
                        padding_hash_algorithm=algorithm(),
                    ),
                ),
                self.assertTrue(
                    encrypt_decrypt_file(
                        BytesIO(),
                        b"secret",
                        b"password123456",
                        padding_hash_algorithm=algorithm(),
                    ),
                ),
            )
            for algorithm in SHA2
        ]

    def test_encrypt_reencrypt_decrypt_file(self):
        [
            (
                self.assertTrue(
                    encrypt_reencrypt_decrypt_file(
                        "./tests/test_file",
                        b"secret",
                        b"new_secret",
                        b"password123456",
                        padding_hash_algorithm=algorithm(),
                    ),
                ),
                self.assertTrue(
                    encrypt_reencrypt_decrypt_file(
                        BytesIO(),
                        b"secret",
                        b"new_secret",
                        b"password123456",
                        padding_hash_algorithm=algorithm(),
                    ),
                ),
            )
            for algorithm in SHA2
        ]

    def test_cipher(self):
        file = "./tests/test_file"
        plaintext = b"secret"
        password = b"password123456"
        [
            (
                self.assertTrue(file_cipher(file, plaintext, password, algorithm())),
                self.assertTrue(
                    file_cipher(BytesIO(), plaintext, password, algorithm())
                ),
            )
            for algorithm in SHA2
        ]

        cipher = fycrypt.FileCipher(file)
        cipher.create(password, plaintext)
        decrypted_text = cipher.read(password)
        self.assertEqual(decrypted_text, plaintext)

        del cipher
        cipher = fycrypt.FileCipher(file)
        decrypted_text = cipher.read(password)
        public_key = cipher.public_key
        self.assertEqual(decrypted_text, plaintext)

        del cipher
        plaintext2 = b"my new secret"
        cipher = fycrypt.FileCipher(file)
        cipher.write(plaintext2, public_key)
        decrypted_text = cipher.read(password)
        self.assertEqual(decrypted_text, plaintext2)

        del cipher
        cipher = fycrypt.FileCipher(file, public_key)
        decrypted_text = cipher.read(password)
        self.assertEqual(decrypted_text, plaintext2)


class LargeTest(unittest.TestCase):
    def test_encrypt_decrypt_file(self):
        with Bar(f"Large Test ERDF", max=len(KEY_SIZES) * len(SHA2)) as bar:
            for key_size in KEY_SIZES:
                for algorithm in SHA2:
                    plaintext = os.urandom(10000)
                    password = os.urandom(32)
                    self.assertTrue(
                        encrypt_decrypt_file(
                            BytesIO(),
                            plaintext,
                            password,
                            padding_hash_algorithm=algorithm(),
                            key_size=key_size,
                        ),
                    )
                    bar.next()
            bar.finish()

    def test_encrypt_reencrypt_decrypt_file(self):
        with Bar(f"Large Test ERDF", max=len(KEY_SIZES) * len(SHA2)) as bar:
            for key_size in KEY_SIZES:
                for algorithm in SHA2:
                    plaintext1 = os.urandom(10000)
                    plaintext2 = os.urandom(8888)
                    password = os.urandom(32)
                    self.assertTrue(
                        encrypt_reencrypt_decrypt_file(
                            BytesIO(),
                            plaintext1,
                            plaintext2,
                            password,
                            padding_hash_algorithm=algorithm(),
                            key_size=key_size,
                        ),
                    )
                    bar.next()
            bar.finish()

    def test_cipher(self):
        with Bar(f"Large Test Cipher", max=len(KEY_SIZES) * len(SHA2)) as bar:
            for key_size in KEY_SIZES:
                for algorithm in SHA2:
                    plaintext = os.urandom(10000)
                    password = os.urandom(32)
                    self.assertTrue(
                        file_cipher(
                            BytesIO(),
                            plaintext,
                            password,
                            padding_hash_algorithm=algorithm(),
                            key_size=key_size,
                        )
                    )
                    bar.next()
            bar.finish()


class RandomTest(unittest.TestCase):
    def test_encrypt_decrypt_file(self):
        def do(times, key_size):
            with Bar(f"encrypt_decrypt_file {key_size}-bit", max=times) as bar:
                for _ in range(times):
                    salt_length = random.randrange(32)
                    size = random.randrange(64)
                    password = os.urandom(32)
                    plaintext = os.urandom(size)
                    hash_algorithm = random.choice(SHA2)
                    self.assertTrue(
                        encrypt_decrypt_file(
                            BytesIO(),
                            plaintext,
                            password,
                            padding_hash_algorithm=hash_algorithm(),
                            salt_length=salt_length,
                            key_size=key_size,
                        )
                    )
                    bar.next()
                bar.finish()

        # do(100, 2048)
        # do(50, 3072)
        # do(10, 4096)

    def test_encrypt_reencrypt_decrypt_file(self):
        def do(times, key_size):
            with Bar(
                f"encrypt_reencrypt_decrypt_file {key_size}-bit", max=times
            ) as bar:
                for _ in range(times):
                    salt_length = random.randrange(32)
                    password = os.urandom(32)
                    plaintext1 = os.urandom(random.randrange(64))
                    plaintext2 = os.urandom(random.randrange(64))
                    hash_algorithm = random.choice(SHA2)
                    self.assertTrue(
                        encrypt_reencrypt_decrypt_file(
                            BytesIO(),
                            plaintext1,
                            plaintext2,
                            password,
                            padding_hash_algorithm=hash_algorithm(),
                            salt_length=salt_length,
                            key_size=key_size,
                        )
                    )
                    bar.next()
                bar.finish()

        do(100, 2048)
        do(50, 3072)
        do(10, 4096)

    def test_cipher(self):
        def do(times, key_size):
            with Bar(f"file_cipher {key_size}-bit", max=times) as bar:
                for _ in range(times):
                    salt_length = random.randrange(32)
                    size = random.randrange(64)
                    password = os.urandom(32)
                    plaintext = os.urandom(size)
                    hash_algorithm = random.choice(SHA2)
                    self.assertTrue(
                        file_cipher(
                            BytesIO(),
                            plaintext,
                            password,
                            padding_hash_algorithm=hash_algorithm(),
                            salt_length=salt_length,
                            key_size=key_size,
                        )
                    )
                    bar.next()
                bar.finish()

        do(100, 2048)
        do(50, 3072)
        do(10, 4096)


if __name__ == "__main__":
    print(f"{hycrypt.__name__} {hycrypt.__version__}")
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(FixedTest))
    suite.addTest(loader.loadTestsFromTestCase(LargeTest))
    suite.addTest(loader.loadTestsFromTestCase(RandomTest))
    unittest.TextTestRunner(verbosity=2).run(suite)
