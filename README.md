# hycrypt
## Hybrid cryptosystem for python

![image info](./images/hybrid_cs_with_password.png)

## Quick Start

For more flexible use:
```python
plaintext = b"secret"
ciphertext, public_key = hycrypt.encrypt_with_password(plaintext, password=b"password1")

decrypted_message = hycrypt.decrypt_with_password(ciphertext, password=b"password1")
assert decrypted_message == plaintext

new_plaintext = b"my new secret"
new_ciphertext = hycrypt.encrypt_with_public_key(previous_data=ciphertext, plaintext=new_plaintext, public_key=public_key)

new_decrypted_message = hycrypt.decrypt_with_password(new_ciphertext, password=b"password1")
assert new_decrypted_message == new_plaintext
```

To install hycrypt using pip:
```
pip install hycrypt
```

## How It Works
