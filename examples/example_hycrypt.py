# hycrypt is licensed under The 3-Clause BSD License, see LICENSE.
# Copyright 2024 Sira Pornsiriprasert <code@psira.me>

import hycrypt

plaintext = b"secret"  # Use b" " to declare bytes string literal
plaintext = "secret".encode()  # Or use str.encode() to convert to bytes

# Encrypting with password
ciphertext, public_key = hycrypt.encrypt_with_password(
    plaintext, password=b"rootadminqwerty123456"
)


# Maybe you want to do some operations with the plaintext
# and return it later but don't want to directly store
# the user's password
def do_something(plaintext):
    grandma_secret = [
        f"{plaintext.decode().capitalize()}",
        "    anyway here's the recipe for brownies:",
        "    1/2cup butter",
        "    2eggs",
        "    1cupsugar",
        "    1/3cup cocoa powder",
        "    2teaspoon vanilla extract",
        "    1/2cup flour",
    ]
    return "\n".join(grandma_secret).encode()


new_plaintext = do_something(plaintext)

# Re-encrypt new data without password using public key
new_ciphertext = hycrypt.encrypt_with_public_key(
    previous_data=ciphertext, plaintext=new_plaintext, public_key=public_key
)

# Decrypting the data
# When the user receive the message, they can decrypt using the password
decrypted_message, _ = hycrypt.decrypt_with_password(
    new_ciphertext, password=b"rootadminqwerty123456"
)
