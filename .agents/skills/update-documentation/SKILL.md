---
name: update-documentation
description: Sync safezip project documentation with source code. Scans code and docs, finds misalignments, and auto-fixes them. Pure agent-based - no Python scripts involved.
---

# Update Documentation Skill

**Operation mode**: Pure agent-based documentation synchronization.

When the user asks to `sync-documentation`, the agent:
1. Scans source code to extract ground truth (public API, CLI commands, exceptions)
2. Scans all documentation files
3. Identifies misalignments between code and docs
4. **Auto-fixes documentation** to match code (reports what was changed)

**This is NOT a Python script** - the agent performs all analysis and edits directly.

## Agent-Based Sync Process

When `sync-documentation` is invoked:

### Step 1: Extract Ground Truth from Code

Scan source code to identify:

- **Public API**: Exports from `__all__` in `__init__.py`
- **CLI commands**: Subcommands defined in `cli/_main.py` (`extract`, `list`)
- **Exceptions**: Exception classes in `_exceptions.py`
- **Classes**: `SafeZipFile` class in `_core.py`

### Step 2: Scan Documentation Files

Read and analyze:

- `README.rst` - Public API, CLI usage, quick start
- `AGENTS.md` - Architecture, code patterns, examples
- `ARCHITECTURE.rst` - Three-phase model, security principles
- `CONTRIBUTING.rst` - Contribution workflow
- `SECURITY.rst` - Security policy and reporting
- `docs/*.rst` - Extended documentation

### Step 3: Identify Misalignments

Compare code ground truth against documentation:

- Missing exception types in tables
- Undocumented CLI commands or options
- Missing API exports
- Broken file path references
- Outdated default limits
- Missing code examples

### Step 4: Auto-Fix Documentation

**The agent directly edits documentation files** to align with code:

- Add missing entries to tables
- Update code examples
- Fix file references
- Add missing sections
- Update default limits

**SKILL.md is NOT modified** - it remains the source of truth for the skill behavior.

### Step 5: Report Changes

After fixing, report:

- Which files were modified
- What changes were made
- Any issues that couldn't be auto-fixed

---

## Documentation Files Overview

| File | Audience | Purpose |
| ---- | -------- | ------- |
| `README.rst` | End users | Public API, quick start, usage examples |
| `AGENTS.md` | AI agents | Mission, architecture, agent workflow, code patterns |
| `ARCHITECTURE.rst` | Developers | Three-phase model, security principles, default limits |
| `CONTRIBUTING.rst` | Contributors | Contribution workflow, testing, release process |
| `SECURITY.rst` | Security researchers | Security policy, reporting vulnerabilities |
| `docs/*.rst` | Users/developers | Extended documentation, API reference |

## When to Update Each File

### README.rst

Update when:

- Public API changes (new functions, parameters, exceptions)
- New CLI commands or options
- New output formats or behavior
- Default limits change
- Installation/requirement changes

Structure to maintain:

- Features list (add new capabilities)
- Quick start examples
- Installation section
- Custom limits examples
- Environment variable overrides
- Default limits table

### AGENTS.md

Update when:

- New parser added (not applicable - safezip has no parsers)
- Resolution pipeline changes
- New exception types
- Testing workflow changes
- Default limits change
- New phases added

Key sections:

- Project mission (never deviate: zero deps, secure defaults, three-phase model)
- Architecture table (if phases/files change)
- Security principles
- Known intentional behaviors
- Agent workflow section
- Testing rules

### ARCHITECTURE.rst

Update when:

- Three-phase model changes
- New phases added
- Default limits change
- Security principles change
- Directory structure changes

Key sections:

- Three-phase model details (Guard, Sandbox, Streamer)
- Security principles
- Default limits table
- Environment variable overrides
- Testing workflow

### CONTRIBUTING.rst

Update when:

- Contribution workflow changes
- Testing procedure changes
- Release process changes
- Code standards change

Key sections:

- Developer prerequisites
- Code standards
- Testing workflow
- Pull request process

### SECURITY.rst

Update when:

- Security policy changes
- Reporting process changes
- Supported versions change

Key sections:

- Security policy
- Supported versions
- Reporting procedure
- Current vulnerabilities

---

## Feature-Specific Documentation Checklist

### Adding a New Exception

1. **README.rst**: Add to exception handling examples
2. **AGENTS.md**: Add to exception table in "Exception handling" section
3. **ARCHITECTURE.rst**: Add to phases table if applicable
4. **CONTRIBUTING.rst**: Update if testing process changed

### Adding New CLI Commands

1. **README.rst**: Add to CLI usage section with examples
2. **AGENTS.md**: Update CLI examples if relevant to agent workflow
3. **ARCHITECTURE.rst**: Add to CLI reference table

### Adding New API Features (new functions, parameters)

1. **README.rst**:
    - Add new function to quick start or new section
    - Add example code block
    - Update features list
2. **AGENTS.md**: Add new code example in "Using safezip" section
3. **ARCHITECTURE.rst**: Update if it affects the three-phase model

### Adding New CLI Options

1. **README.rst**: Add to relevant command examples
2. **AGENTS.md**: Update CLI examples if relevant to agent workflow

### Changing Default Limits

1. **README.rst**: Update default limits table
2. **AGENTS.md**: Update default limits table
3. **ARCHITECTURE.rst**: Update default limits table
4. **All files**: Update environment variable documentation

---

## Code Block Naming Convention

AGENTS.md uses executable code blocks with `name=<test_name>` attributes:

````markdown
```python name=test_example
# Code here
```

<!-- continue: test_example -->
```python name=test_example_part2
# Continues previous block, imports/vars in scope
```
````

When adding examples:

- Use descriptive names: `test_<feature>_<scenario>`
- Use `<!-- continue: <name> -->` to chain related blocks
- Ensure imports are at the top of the first block

## Documentation Standards

### RST Formatting

- Line length: 88 characters
- Use `.. code-block:: python` with `:name: test_<name>` for Python
- Use `.. code-block:: sh` for shell commands
- Use `.. note::` for callouts

### Code Examples

All code examples in AGENTS.md (and other Markdown files) should be runnable
tests. Use the `name=` attribute to prefix the block name with `test_`:

````markdown
```python name=test_feature_name

from safezip import safe_extract, SafezipError
result = safe_extract("path/to/file.zip", "/tmp/extract/")
```
````

All code examples in README.rst (and other reStructuredText files) should be
runnable tests. Use the `:name:` attribute to prefix the block name with `test_`:

```rst
.. code-block:: python
    :name: test_feature_name

   from safezip import safe_extract, SafezipError
   result = safe_extract("path/to/file.zip", "/tmp/extract/")
```

### Cross-References

- Link to related docs: ``See `ARCHITECTURE.rst`_``
- Reference other sections: ``See `Default limits`_``

## Validation Checklist

Before finishing documentation updates:

- [ ] README.rst examples match actual API
- [ ] AGENTS.md code blocks have proper `name=` attributes
- [ ] ARCHITECTURE.rst tables include all current exceptions
- [ ] CONTRIBUTING.rst reflects current contribution process
- [ ] SECURITY.rst is up to date
- [ ] All RST files pass linting
- [ ] Cross-references between docs are valid
- [ ] File paths in docs match actual paths

## What NOT to Document

Do NOT modify documentation that is auto-generated or managed separately.

---

**Use Agent-Based Sync (`sync-documentation`) when:**
- User explicitly asks to "sync documentation"
- You need documentation auto-fixed, not just validated
- You want an interactive, conversational workflow
