Full project source-tree
========================

Below is the layout of the project (to 10 levels), followed by
the contents of each key file.

.. code-block:: text
   :caption: Project directory layout

   safezip/
   ├── docs
   │   ├── conf.py
   │   ├── contributor_guidelines.rst
   │   ├── documentation.rst
   │   ├── full-llms.rst
   │   ├── index.rst
   │   ├── llms.rst
   │   └── package.rst
   ├── src
   │   └── safezip
   │       ├── tests
   │       │   ├── __init__.py
   │       │   ├── conftest.py
   │       │   ├── test_guard.py
   │       │   ├── test_integration.py
   │       │   ├── test_sandbox.py
   │       │   └── test_streamer.py
   │       ├── __init__.py
   │       ├── _core.py
   │       ├── _events.py
   │       ├── _exceptions.py
   │       ├── _guard.py
   │       ├── _sandbox.py
   │       ├── _streamer.py
   │       └── py.typed
   ├── .coveralls.yml
   ├── conftest.py
   ├── CONTRIBUTING.rst
   ├── docker-compose.yml
   ├── Dockerfile
   ├── Makefile
   ├── pyproject.toml
   ├── README.rst
   └── tox.ini

.coveralls.yml
--------------

.. literalinclude:: ../.coveralls.yml
   :language: yaml
   :caption: .coveralls.yml

CONTRIBUTING.rst
----------------

.. literalinclude:: ../CONTRIBUTING.rst
   :language: rst
   :caption: CONTRIBUTING.rst

README.rst
----------

.. literalinclude:: ../README.rst
   :language: rst
   :caption: README.rst

conftest.py
-----------

.. literalinclude:: ../conftest.py
   :language: python
   :caption: conftest.py

docker-compose.yml
------------------

.. literalinclude:: ../docker-compose.yml
   :language: yaml
   :caption: docker-compose.yml

docs/conf.py
------------

.. literalinclude:: conf.py
   :language: python
   :caption: docs/conf.py

docs/contributor_guidelines.rst
-------------------------------

.. literalinclude:: contributor_guidelines.rst
   :language: rst
   :caption: docs/contributor_guidelines.rst

docs/documentation.rst
----------------------

.. literalinclude:: documentation.rst
   :language: rst
   :caption: docs/documentation.rst

docs/full-llms.rst
------------------

.. literalinclude:: full-llms.rst
   :language: rst
   :caption: docs/full-llms.rst

docs/index.rst
--------------

.. literalinclude:: index.rst
   :language: rst
   :caption: docs/index.rst

docs/llms.rst
-------------

.. literalinclude:: llms.rst
   :language: rst
   :caption: docs/llms.rst

docs/package.rst
----------------

.. literalinclude:: package.rst
   :language: rst
   :caption: docs/package.rst

pyproject.toml
--------------

.. literalinclude:: ../pyproject.toml
   :language: toml
   :caption: pyproject.toml

src/safezip/__init__.py
-----------------------

.. literalinclude:: ../src/safezip/__init__.py
   :language: python
   :caption: src/safezip/__init__.py

src/safezip/_core.py
--------------------

.. literalinclude:: ../src/safezip/_core.py
   :language: python
   :caption: src/safezip/_core.py

src/safezip/_events.py
----------------------

.. literalinclude:: ../src/safezip/_events.py
   :language: python
   :caption: src/safezip/_events.py

src/safezip/_exceptions.py
--------------------------

.. literalinclude:: ../src/safezip/_exceptions.py
   :language: python
   :caption: src/safezip/_exceptions.py

src/safezip/_guard.py
---------------------

.. literalinclude:: ../src/safezip/_guard.py
   :language: python
   :caption: src/safezip/_guard.py

src/safezip/_sandbox.py
-----------------------

.. literalinclude:: ../src/safezip/_sandbox.py
   :language: python
   :caption: src/safezip/_sandbox.py

src/safezip/_streamer.py
------------------------

.. literalinclude:: ../src/safezip/_streamer.py
   :language: python
   :caption: src/safezip/_streamer.py

src/safezip/tests/__init__.py
-----------------------------

.. literalinclude:: ../src/safezip/tests/__init__.py
   :language: python
   :caption: src/safezip/tests/__init__.py

src/safezip/tests/conftest.py
-----------------------------

.. literalinclude:: ../src/safezip/tests/conftest.py
   :language: python
   :caption: src/safezip/tests/conftest.py

src/safezip/tests/test_guard.py
-------------------------------

.. literalinclude:: ../src/safezip/tests/test_guard.py
   :language: python
   :caption: src/safezip/tests/test_guard.py

src/safezip/tests/test_integration.py
-------------------------------------

.. literalinclude:: ../src/safezip/tests/test_integration.py
   :language: python
   :caption: src/safezip/tests/test_integration.py

src/safezip/tests/test_sandbox.py
---------------------------------

.. literalinclude:: ../src/safezip/tests/test_sandbox.py
   :language: python
   :caption: src/safezip/tests/test_sandbox.py

src/safezip/tests/test_streamer.py
----------------------------------

.. literalinclude:: ../src/safezip/tests/test_streamer.py
   :language: python
   :caption: src/safezip/tests/test_streamer.py
