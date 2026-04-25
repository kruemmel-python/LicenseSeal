# Packaging Fix

This build pins setuptools package discovery to `licenseseal*` only.

It prevents editable installs from failing when unrelated top-level folders
such as `Notebook_LM/` are present in the checkout directory.

Fixed:
- `project.license` now uses SPDX string syntax.
- `[tool.setuptools.packages.find]` explicitly includes only `licenseseal` and `licenseseal.*`.
- `[full]` includes queue/bot dependencies used by the enterprise extensions.
