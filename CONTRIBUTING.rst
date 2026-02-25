Contributor guidelines
======================

.. _safezip: https://github.com/barseghyanartur/safezip/
.. _uv: https://docs.astral.sh/uv/
.. _tox: https://tox.wiki
.. _ruff: https://beta.ruff.rs/docs/
.. _doc8: https://doc8.readthedocs.io/
.. _pre-commit: https://pre-commit.com/#installation
.. _issues: https://github.com/barseghyanartur/safezip/issues
.. _discussions: https://github.com/barseghyanartur/safezip/discussions
.. _pull request: https://github.com/barseghyanartur/safezip/pulls
.. _versions manifest: https://github.com/actions/python-versions/blob/main/versions-manifest.json

Developer prerequisites
-----------------------

pre-commit
~~~~~~~~~~

Refer to `pre-commit`_ for installation instructions.

TL;DR:

.. code-block:: sh

    curl -LsSf https://astral.sh/uv/install.sh | sh  # Install uv
    uv tool install pre-commit                        # Install pre-commit
    pre-commit install                                # Install hooks

Installing `pre-commit`_ ensures all contributions adhere to the project's
code quality standards.

Code standards
--------------

`ruff`_ and `doc8`_ are triggered automatically by `pre-commit`_.

To run checks manually:

.. code-block:: sh

    make doc8
    make ruff

Virtual environment
-------------------

.. code-block:: sh

    uv sync
    uv pip install -e .[all]

Testing
-------

**All tests must be run inside Docker.**  This prevents accidental extraction
of malicious test archives from reaching the host filesystem.

.. code-block:: sh

    make docker-test

To test a single environment:

.. code-block:: sh

    make docker-test-env ENV=py312

For an interactive shell inside the container:

.. code-block:: sh

    make docker-shell

In any case, GitHub Actions runs the full matrix automatically on every push.

Releases
--------
**Build the package for releasing:**

.. code-block:: sh

    make package-build

----

**Test the built package:**

.. code-block:: sh

    make check-package-build

----

**Make a test release (test.pypi.org):**

.. code-block:: sh

    make test-release

----

**Release (pypi.org):**

.. code-block:: sh

    make release

Adding tests
------------

- All test archives must be crafted programmatically in ``conftest.py`` using
  Python's ``struct`` module or ``zipfile``.  Do not commit pre-built ``.zip``
  files.
- Every new security check must have a corresponding test in the relevant
  ``test_*.py`` file.
- Integration tests must verify that no partial files remain on disk after a
  security abort (atomic write contract).

Pull requests
-------------

Open a `pull request`_ to the ``dev`` branch only. Never directly to ``main``.

.. note::

    Create pull requests to the ``dev`` branch only!

Examples of welcome contributions:

- Fixing documentation typos or improving explanations.
- Adding test cases for new edge cases.
- Extending support for additional archive attack vectors.
- Improving error messages.

General checklist
~~~~~~~~~~~~~~~~~

- Does your change require documentation updates?
- Does your change require new tests?
- Does your change add any external dependencies?
  If so, reconsider: ``safezip`` is intentionally dependency-free.

When fixing bugs
~~~~~~~~~~~~~~~~

- Add a regression test that reproduces the bug before your fix.

When adding a new feature
~~~~~~~~~~~~~~~~~~~~~~~~~

- Update ``README.rst`` (quick start, default limits table if relevant).
- Update ``plan.rst`` if the architectural design changes.
- Add appropriate tests in the correct ``test_*.py`` file.

GitHub Actions
--------------

Tests run on Python 3.10–3.14 (all non-EOL versions).  See the
`versions manifest`_ for the full list of available Python versions.

Questions
---------

Ask on GitHub `discussions`_.

Issues
------

Report bugs or request features on GitHub `issues`_.

**Do not report security vulnerabilities on GitHub.**
Contact the author directly at artur.barseghyan@gmail.com.
