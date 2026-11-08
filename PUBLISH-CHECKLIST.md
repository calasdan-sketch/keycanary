# Publishing keycanary to PyPI (plain steps)

Status when this was written: keycanary has never been published. A read-only
`pip index versions keycanary` found no such package (if that machine's network
was filtered, treat that as "not confirmed"; check pypi.org/project/keycanary
yourself before step 1).

**Version to release: 0.2.0.** It is the first release under the name
`keycanary`, so nothing breaks for existing users. It is already set to 0.2.0 in
`pyproject.toml`, `keycanary/__init__.py` and `CHANGELOG.md`, and a test fails if
they ever disagree. Do not change it unless you want a different number.

## Decide first (two minutes)

1. **Is the source repository public?** The package page currently shows no
   Homepage/Source links, on purpose. If the repository is public, add three
   lines to `pyproject.toml` before you build:

       [project.urls]
       Homepage = "https://github.com/<owner>/keycanary"
       Source = "https://github.com/<owner>/keycanary"
       Issues = "https://github.com/<owner>/keycanary/issues"

   (then update the one test that guards this, `test_no_package_urls_while_repo_visibility_is_unsettled`).
   If it is private, leave it alone; a link to a private page looks broken.
2. **Author name** is "Calas Automations Inc." with no email. PyPI shows only
   that name. Leave it.

## Check (before you upload anything)

From the project folder, in a terminal:

    python -m pip install --upgrade build twine pytest ruff
    ruff check .
    python -m pytest -q tests            # about 3 to 6 minutes; expect "passed", no "failed"
    python bench/run.py --check          # expect: matches a fresh run
    python -m build                      # makes two files in dist/
    python -m twine check dist/*         # expect PASSED twice

Then prove the built file works on its own (not your working folder):

    python -m venv /tmp/kc-try
    /tmp/kc-try/bin/pip install dist/keycanary-0.2.0-py3-none-any.whl
    cd /tmp && /tmp/kc-try/bin/keycanary --version     # keycanary 0.2.0 (Calas Automations Inc.)
    /tmp/kc-try/bin/keycanary --profile example-literal-masker --suite control --fail-on-leak && echo OK

(On Windows use `Scripts\keycanary.exe` instead of `bin/keycanary`. Windows has
never been run for this project; see the README's limits.)

## Upload (your step; this is the part only you can do)

You are signed in to PyPI yourself. Practise on TestPyPI first if you like:

    python -m twine upload --repository testpypi dist/*
    python -m twine upload dist/*

Uploading cannot be undone: PyPI never lets the same version number be used
twice, even after deleting. If something is wrong, fix it and release 0.2.1.

## After

- In a fresh folder: `pip install keycanary` then `keycanary --version`.
- Only now may the README say `pip install keycanary` works. It currently says
  it does not (README, "Python 3.11, 3.12 and 3.13..." paragraph), so edit that
  paragraph, bump nothing, and release 0.2.1 if you want the README on PyPI to say so.
- Do not tag or push anything from this checklist; that is a separate decision.
