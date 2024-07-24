# hycrypt is licensed under The 3-Clause BSD License, see LICENSE.
# Copyright 2024 Sira Pornsiriprasert <code@psira.me>

import os
import sys

import hycrypt

sys.path.insert(0, os.path.abspath("../.."))

project = "hycrypt"
copyright = "2024, Sira Pornsiriprasert"
author = "Sira Pornsiriprasert"
release = hycrypt.__version__

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
]

autosummary_generate = True

autodoc_typehints = "none"

napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_include_init_with_doc = False
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = False
napoleon_use_admonition_for_notes = False
napoleon_use_admonition_for_references = False
napoleon_use_ivar = False
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_preprocess_types = True
napoleon_type_aliases = {"cryptography.hazmat.primitives.hashes.SHA256", "SHA256"}
napoleon_attr_annotations = True


templates_path = ["_templates"]
exclude_patterns = []


html_theme = "pydata_sphinx_theme"
html_static_path = ["_static"]
html_css_files = [
    "custom.css",
    # "theme.css",
]

import re

patterns = [
    (r"<cryptography\.hazmat\.primitives\.hashes\.SHA256\s+object>", "SHA256()"),
]


def process_signature(app, what, name, obj, options, signature, return_annotation):
    if signature:
        for regex, replace in patterns:
            pattern = re.compile(regex)
            signature = pattern.sub(replace, signature)
    return (signature, return_annotation)


hycrypt.__doc__ = ""

def setup(app):
    app.add_css_file("custom.css")
    # app.add_css_file("theme.css")
    # app.connect("builder-inited", override_docstrings)
    app.connect("autodoc-process-signature", process_signature)
