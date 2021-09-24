# PQencryption

A Python library for classical and post-quantum cryptography.

It wraps in one unified interface:

- AES256
- Salsa20 256
- [McBits](https://tungchou.github.io/mcbits/)
- SHA256
- Key generation
  - Symmetric keys
  - Public/private keys
  - Signing/verification keys

## Installation

- Install dependencies for `pycrypto`. For example in Ubuntu:
```
sudo apt-get install build-essential libssl-dev libffi-dev python-dev
```

- Set up a virtual python environment in the folder of your project.
```
pip install --user pipenv
pipenv --two shell
```

- Navigate to the root folder of this repository and install python dependencies from there. Also install the PQencryption package.
```
pipenv install
pipenv install ./PQencryption
```

## Usage

Use the package as indicated in the file [crypto_examples.py](PQencryption/crypto_examples.py). Example for generating a public-private key pair:
```
from PQencryption import utilities
public_key, private_key = utilities.generate_public_private_keys()
```
