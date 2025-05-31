..
   hycrypt is licensed under The 3-Clause BSD License, see LICENSE.
   Copyright 2024 Sira Pornsiriprasert <code@psira.me>


Hycrypt
=======

**Stateless-overwrite hybrid cryptosystem for Python**

.. image:: https://img.shields.io/badge/License-BSD--3--Clause-brightgreen.svg
   :target: https://opensource.org/license/BSD-3-clause
.. image:: https://img.shields.io/pypi/v/hycrypt?label=pypi%20package&color=a190ff
   :target: https://pypi.org/project/hycrypt/
.. image:: https://img.shields.io/pepy/dt/hycrypt
   :target: https://pepy.tech/projects/hycrypt
.. image:: https://img.shields.io/badge/Docs-github.io-blue
   :target: https://p-sira.github.io/hycrypt/

----

.. image:: ./../../images/hybrid-cs.svg
   :alt: Hybrid cryptosystem diagram

----

**Hycrypt** is a stateless-overwrite hybrid cryptosystem designed for **secure data encryption and password-free updates**. This makes it ideal for secure communication and storage systems where only the recipient can decrypt the data — yet the data can be updated without the password.

The caveat is that this cryptosystem does not guarantee authenticity of the message. Anyone with the public key can overwrite the message. However, without the private key (or password), they cannot read the encrypted message.

Features
--------

- 🔒 **Hybrid encryption** using RSA + AES-CBC + HMAC
- 🔁 **Stateless overwrite** using only the public key, removing the need to retain user secrets
- 🔑 **Password-based protection** using PBKDF2
- 📦 **Simple, yet flexible API** for file-based and in-memory encryption

Quick Start
-----------

Using FileCipher to manage file encryption:

.. code-block:: python

    from hycrypt.file_cryptosystem import FileCipher

    file = "home/data.txt"
    plaintext = b"secret"
    password = b"correcthorsebatterystaple"
    cipher = FileCipher(file)

    cipher.create(password)
    cipher.write(plaintext)
    decrypted_text = cipher.read(password)

For more flexible use:

.. code-block:: python

    import hycrypt

    plaintext = b"secret"
    ciphertext, public_key = hycrypt.encrypt_with_password(plaintext, password=b"password1")

    decrypted_message = hycrypt.decrypt_with_password(ciphertext, password=b"password1")
    assert decrypted_message == plaintext

    new_plaintext = b"my new secret"
    new_ciphertext = hycrypt.encrypt_with_public_key(previous_data=ciphertext, plaintext=new_plaintext, public_key=public_key)

    new_decrypted_message = hycrypt.decrypt_with_password(new_ciphertext, password=b"password1")
    assert new_decrypted_message == new_plaintext

To install hycrypt using pip:

.. code-block:: bash

    pip install hycrypt

How It Works
------------

.. image:: ./../../images/hybrid-cs-with-password.svg
   :alt: Hybrid cryptosystem with password

Encryption
^^^^^^^^^^

1. A **symmetric key** is randomly generated to encrypt the plaintext into ciphertext. The encryption uses `Fernet <https://cryptography.io/en/latest/fernet/>`_ implementation by `cryptography <https://github.com/pyca/cryptography>`_.
2. An **RSA key pair** (private and public key) is generated.
3. The **public key** is used to encrypt the symmetric key. The public key can be shared safely.
4. The user selects a **password**.
5. The password is combined with a **random salt** to produce a **password-derived symmetric key** using `PBKDF2`.
6. The password-derived key is used to **encrypt the private key**.
7. The ciphertext is stored along with the encrypted symmetric key, the salt, and the encrypted private key.

Decryption
^^^^^^^^^^

1. The user inputs the **password**.
2. The password is combined with the stored **salt** using `PBKDF2` to recreate the same **password-derived symmetric key**.
3. The password-derived key **decrypts the private key** in the file.
4. The recovered private key decrypts the **symmetric key** that was used to encrypt the file data.
5. The symmetric key decrypts the ciphertext into plaintext.

Overwriting Data Without Password
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. A new **symmetric key** is generated randomly.
2. The symmetric key encrypts the **new plaintext** into ciphertext.
3. The original **public key** is used to encrypt the new symmetric key.
4. The file is updated with the new encrypted symmetric key and the new ciphertext.

Despite the writer not knowing the password, the data can be overwritten using the public key. The encrypted private key remains a secret. Because the encrypted private key corresponds to the public key, the recipient who knows the password can still decrypt the data.

Disclaimer
----------

Hycrypt is intended for educational and experimental uses. While it employs reasonably secure cryptographic practices, it has not undergone formal security audits. Hence, it is not recommended for production environment without thorough review and modification. Consider opening an issue or submitting a pull request for potential issues and improvement.

Contents
--------

.. toctree::
   :maxdepth: 2

   install
   base_module
   file_cryptosystem