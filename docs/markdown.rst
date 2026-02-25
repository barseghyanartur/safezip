Markdown
========

.. External references
.. _Markdown: https://daringfireball.net/projects/markdown/
.. _pytest: https://docs.pytest.org
.. _Django: https://www.djangoproject.com
.. _pip: https://pypi.org/project/pip/
.. _uv: https://pypi.org/project/uv/
.. _fake.py: https://github.com/barseghyanartur/fake.py
.. _boto3: https://github.com/boto/boto3
.. _moto: https://github.com/getmoto/moto
.. _openai: https://github.com/openai/openai-python
.. _Ollama: https://github.com/ollama/ollama

Usage examples
--------------

Any fenced code block with a recognized Python language tag (e.g., ``python``,
``py``) will be collected and executed automatically, if
your `pytest`_ :ref:`configuration <configuration>` allows that.

Standalone code blocks
~~~~~~~~~~~~~~~~~~~~~~

.. note:: Note that ``name`` value has a ``test_`` prefix.

*Filename: README.md*

.. code-block:: markdown

    ```python name=test_basic_example
    import math

    result = math.pow(3, 2)
    assert result == 9
    ```

----

Grouping multiple code blocks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It's possible to split one logical test into multiple blocks.
They will be tested under the first ``name`` specified.
Note the ``<!-- continue: test_group_new_syntax -->`` directive.

.. note:: Note that ``continue`` directive of
          the ``test_grouping_example_part_2``
          and ``test_grouping_example_part_3`` refers to
          the ``test_grouping_example``.

*Filename: README.md*

.. code-block:: markdown

    ```python name=test_grouping_example
    x = 1
    ```

    Some intervening text.

    <!-- continue: test_grouping_example -->
    ```python name=test_grouping_example_part_2
    y = x + 1  # Uses x from the first snippet
    assert y == 2
    ```

    Some intervening text.

    <!-- continue: test_grouping_example -->
    ```python name=test_grouping_example_part_3

    print(y)  # Uses y from the previous snippet
    ```

The above mentioned three snippets will run as a single test.

.. note:: 
    
    Note, that nameless code block can't be served as a first block in a 
    group, as there is no way to refer to it. Nameless code blocks can only be 
    used as continuing blocks in a group.

----

Async
~~~~~
You can use `top-level await` in your code blocks. The code will be
automatically wrapped in an async function.

*Filename: README.md*

.. code-block:: markdown

    ```python name=test_async_example
    import asyncio

    result = await asyncio.sleep(0.1, result=42)
    assert result == 42
    ```

----

Adding pytest markers to code blocks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It's possible to add custom pytest markers to your code blocks. That allows
adding custom logic and mocking in your ``conftest.py``.

In the example below, ``django_db`` marker is added to the code block.

.. note:: Note the ``pytestmark`` directive ``django_db`` marker.

*Filename: README.md*

.. code-block:: markdown

    <!-- pytestmark: django_db -->
    ```python name=test_django
    from django.contrib.auth.models import User

    user = User.objects.first()
    ```

Running pytest-style tests within code blocks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``pytestrun`` marker allows code blocks to be executed as standalone pytest
suites. Unlike standard code blocks that are simply executed with ``exec()``,
blocks with the ``pytestrun`` marker support full pytest functionality including
test classes, fixtures, and setup/teardown within documentation snippets.

.. note:: Note the ``pytestmark`` directive ``pytestrun`` marker.

*Filename: README.md*

.. code-block:: markdown

    <!-- pytestmark: pytestrun -->
    ```python name=test_pytestrun_example
    import pytest

    class TestSystemInfo:

        @pytest.fixture
        def system_name(self):
            return "Linux"

        @pytest.fixture
        def version_number(self):
            return 5

        def test_combined_info(self, system_name, version_number):
            info = f"{system_name} v{version_number}"
            assert info == "Linux v5"

        def test_name_only(self, system_name):
            assert system_name.isalpha()
    ```

Requesting pytest fixtures for code blocks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It's possible to request existing or custom pytest fixtures for code blocks.
That allows adding custom logic and mocking in ``conftest.py``.

In the example below, ``tmp_path`` fixture is requested for the code block.

.. note:: Note the ``pytestfixture`` directive ``tmp_path`` fixture.

*Filename: README.md*

.. code-block:: markdown

    <!-- pytestfixture: tmp_path -->
    ```python name=test_path
    d = tmp_path / "sub"
    d.mkdir()  # Create the directory
    assert d.is_dir()  # Verify it was created and is a directory
    ```

----

Let's consider a sample `openai`_ code to ask LLM to tell a joke.
In the example below, ``openai_mock`` fixture is requested for 
the code block.

.. note:: Note the ``pytestfixture`` directive ``openai_mock`` fixture.

*Filename: README.md*

.. code-block:: markdown

    <!-- pytestfixture: openai_mock -->
    ```python name=test_tell_me_a_joke
    from openai import OpenAI

    client = OpenAI()
    completion = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "developer", "content": "You are a famous comedian."},
            {"role": "user", "content": "Tell me a joke."},
        ],
    )

    assert isinstance(completion.choices[0].message.content, str)
    ```

----

Multiple ``pytestfixture`` directives are supported. Add one on each line.

.. note::

    When combining ``pytestfixture`` and ``continue`` directives together,
    request pytest-fixtures only in the first ``code-block``, as they will
    automatically become available in all continuing blocks.

Custom pytest-fixtures are supported as well. Just define them in
your ``conftest.py`` file.

Customisation/hooks
-------------------
Tests can be extended and fine-tuned using `pytest`_'s standard hook system.

Below is an example workflow:

1. **Add custom pytest markers** to the code
   blocks (``fakepy``, ``aws``, ``openai``).
2. **Implement pytest hooks** in ``conftest.py`` to react to those markers.

Add custom pytest markers
~~~~~~~~~~~~~~~~~~~~~~~~~

Add ``fakepy`` marker
^^^^^^^^^^^^^^^^^^^^^

The example code below will generate a PDF file with random text
using `fake.py`_ library. Note, that a ``fakepy`` marker is added to
the code block.

In the `Implement pytest hooks`_ section, you will see what can be done
with the markers.

.. note:: Note the ``pytestmark`` directive ``fakepy`` marker.

*Filename: README.md*

.. code-block:: markdown

    <!-- pytestmark: fakepy -->
    ```python name=test_create_pdf_file
    from fake import FAKER

    FAKER.pdf_file()
    ```

Add ``aws`` marker
^^^^^^^^^^^^^^^^^^

Sample `boto3`_ code to create a bucket on AWS S3.

.. note:: Note the ``pytestmark`` directive ``aws`` marker.

*Filename: README.md*

.. code-block:: markdown

    <!-- pytestmark: aws -->
    ```python name=test_create_bucket
    import boto3

    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="my-bucket")
    assert "my-bucket" in [b["Name"] for b in s3.list_buckets()["Buckets"]]
    ```

----

Implement pytest hooks
~~~~~~~~~~~~~~~~~~~~~~

.. include:: _implement_pytest_hooks.rst
