..
   hycrypt is licensed under The 3-Clause BSD License, see LICENSE.
   Copyright 2024 Sira Pornsiriprasert <code@psira.me>


Installation
============

To install hycrypt using ``pip``:

.. code-block:: console

    pip install hycrypt


Or build the module yourself. Make sure you have python-build installed, if not:

.. code-block:: console

    sudo pacman -Syu python-build

For python-build installation on your specific system, please refer to your favorite package manager's manual.
Once, python-build is installed:

.. code-block:: console

    git clone https://gitlab.com/hycrypt/hycrypt
    cd hycrypt
    python -m build
    pip install .
