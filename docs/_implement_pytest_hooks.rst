In the example below:

- `moto`_ is used to mock AWS S3 service for all tests marked as ``aws``.
- ``openai_mock`` is used to mock OpenAI API for tests requiring that.
- ``FILE_REGISTRY.clean_up()`` is executed at the end of each test marked
  as ``fakepy``.

*Filename: conftest.py*

.. literalinclude:: ../conftest.py
    :name: test_conftest.py
