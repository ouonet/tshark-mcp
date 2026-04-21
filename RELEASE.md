# Release Guide

## Versioning Strategy

This project follows Semantic Versioning:

1. Patch release (`0.1.0` -> `0.1.1`): bug fixes and compatibility fixes.
2. Minor release (`0.1.0` -> `0.2.0`): backward-compatible new tools or features.
3. Major release (`0.x` -> `1.0.0` and beyond): breaking API/tool changes.

## Recommended Next Version

Given the recent compatibility and packaging improvements, the next version should be `0.1.1`.

## Pre-release Checklist

1. Update `version` in `pyproject.toml`.
2. Run release checks:

```bash
uv run python scripts/release_check.py
```

3. Commit release changes.
4. Create a tag:

```bash
git tag v0.1.1
```

5. Push commit and tag:

```bash
git push
git push origin v0.1.1
```

6. Publish to PyPI with uv:

```bash
uv publish
```

## Release Notes Template

Use the following template in your GitHub Release:

```markdown
## vX.Y.Z

### Highlights
- Short summary of the release goal.

### Added
- New features or tools.

### Changed
- Improvements to behavior, docs, or packaging.

### Fixed
- Bug fixes and compatibility fixes.

### Notes
- Breaking changes (if any):
- Upgrade or migration notes:
```
