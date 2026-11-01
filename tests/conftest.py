import pytest

from arcampe import assess, poam
from arcampe.integrations.connectors import collect_all


@pytest.fixture(scope="session")
def findings():
    return assess.run_all()


@pytest.fixture(scope="session")
def evidence():
    return collect_all()


@pytest.fixture(scope="session")
def poam_items(findings):
    return poam.build(findings)
