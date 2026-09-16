from pathlib import Path

import pytest

from arxml_secdiff import graph as graph_mod
from arxml_secdiff import parser, secoc

FIXTURES = Path(__file__).parent / "fixtures"
DATA = Path(__file__).parent.parent / "data"

# Prototype paths used across the multi-instance fixtures.
DL = "/T/Swc/Top/dl"
DR = "/T/Swc/Top/dr"
CTRL = "/T/Swc/Top/ctrl"
TOP = "/T/Swc/Top"


def _model(*names):
    return parser.parse([FIXTURES / name for name in names])


@pytest.fixture
def sr():
    return _model("minimal_sr.arxml")


@pytest.fixture
def cs():
    return _model("minimal_cs.arxml")


@pytest.fixture
def multi():
    """One type instantiated twice, plus a delegation connector. No ECU mapping."""
    return _model("multi_instance.arxml")


@pytest.fixture
def mapped():
    """Same architecture as `multi`, plus topology and SWC-TO-ECU-MAPPING.

    Parsed as two files together, which is also the multi-file index test.
    """
    return _model("multi_instance.arxml", "system_two_ecu.arxml")


@pytest.fixture
def alt_ns():
    return _model("alt_namespace.arxml")


@pytest.fixture
def parse_dangling():
    """Refs pointing outside the package set must be recorded, not raised."""
    return _model("dangling_ref.arxml")


@pytest.fixture
def bus():
    """Two ECUs, one connector, two signals - one SecOC-protected, one not."""
    return _model("bus_signals.arxml")


@pytest.fixture
def overlay_path():
    return FIXTURES / "secoc_overlay.yaml"


# The veh_* trio is one architecture in three states, and is the backbone of the
# diff, reachability and severity tests. v1 is the before; v2 and v3 each carry a
# single, separately-diagnosable regression relative to it.
TEL = "/V/Swc/Veh/tel"
GW = "/V/Swc/Veh/gw"
ABS = "/V/Swc/Veh/abs"
BRAKE = "/V/Swc/Veh/brake"


def _annotated(name):
    """Parse a snapshot and return (model, SecOC-annotated graph)."""
    model = _model(name)
    return model, secoc.annotate(graph_mod.build(model), model)


@pytest.fixture
def veh1():
    """before: no gw -> abs link, so telematics cannot reach the brake."""
    return _annotated("veh_v1.arxml")


@pytest.fixture
def veh1_again():
    """A second independent parse of the before, for determinism checks."""
    return _annotated("veh_v1.arxml")


@pytest.fixture
def veh2():
    """Adds the gw -> abs link and drops SecOC from the telematics command."""
    return _annotated("veh_v2.arxml")


@pytest.fixture
def veh3():
    """Rehosts `abs`, putting the brake request on the bus unauthenticated."""
    return _annotated("veh_v3.arxml")


@pytest.fixture
def real():
    """The upstream EcuExtract.arxml, used as a golden regression fixture."""
    path = DATA / "EcuExtract.arxml"
    if not path.exists():
        pytest.skip("data/EcuExtract.arxml not present")
    return parser.parse([path])


@pytest.fixture
def build():
    return graph_mod.build


# -- path-level fixtures, for the pipeline and CLI, which take files not models -----

V1 = str(FIXTURES / "veh_v1.arxml")
V2 = str(FIXTURES / "veh_v2.arxml")
V3 = str(FIXTURES / "veh_v3.arxml")

#: The seeds a programme's TARA would supply for the veh trio.
VEH_ROLES = {
    "entry_points": [
        {"node": TEL, "reason": "cellular telematics uplink, external attack surface"}
    ],
    "critical": [
        {"node": BRAKE, "asil": "D", "reason": "service brake actuation"},
        {"node": ABS, "asil": "C", "reason": "anti-lock braking"},
    ],
}


@pytest.fixture
def roles_file(tmp_path):
    """VEH_ROLES written to YAML, for the paths that only accept a file."""
    import yaml

    path = tmp_path / "roles.yaml"
    path.write_text(yaml.safe_dump(VEH_ROLES))
    return str(path)
