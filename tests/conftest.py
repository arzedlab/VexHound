import pathlib

import pytest

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def fixture(name):
    """Return a fixture path, or skip the test if that binary is not present."""
    p = FIXTURES / name
    if not p.exists():
        pytest.skip(f"fixture {name} not available")
    return str(p)
