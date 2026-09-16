"""SecOC tests, centred on the three-valued `authenticated` result.

None (not applicable) must stay distinct from False (applicable and missing).
Collapsing them is what turns a report into noise, because most connectors in any
real ECU extract are RTE-internal.
"""

from arxml_secdiff import secoc

CMD_PDU = "/B/Comm/CmdIPdu"
DIAG_PDU = "/B/Comm/DiagIPdu"
HEAD = "/B/Swc/Sys/head"
GW = "/B/Swc/Sys/gw"


class TestFromArxml:
    def test_secured_pdu_yields_a_profile_for_its_payload(self, bus):
        profiles = secoc.from_arxml(bus)
        assert set(profiles) == {CMD_PDU}
        assert profiles[CMD_PDU].authenticated is True
        assert profiles[CMD_PDU].source == secoc.FROM_ARXML

    def test_security_parameters_are_read(self, bus):
        profile = secoc.from_arxml(bus)[CMD_PDU]
        assert profile.freshness_bits == 8
        assert profile.auth_info_bits == 32

    def test_unwrapped_pdu_gets_no_profile(self, bus):
        assert DIAG_PDU not in secoc.from_arxml(bus)

    def test_upstream_sample_has_none(self, real):
        assert secoc.from_arxml(real) == {}


class TestOverlay:
    def test_loads_yaml_keyed_by_pdu(self, overlay_path):
        profiles = secoc.load_overlay(overlay_path)
        assert set(profiles) == {DIAG_PDU}
        assert profiles[DIAG_PDU].authenticated is False
        assert profiles[DIAG_PDU].source == secoc.FROM_OVERLAY

    def test_arxml_evidence_beats_overlay_assumption(self, bus, overlay_path):
        """A SECURED-I-PDU in the file must win over a contradicting overlay."""
        forged = {
            CMD_PDU: secoc.SecOcProfile(
                pdu=CMD_PDU, authenticated=False, source=secoc.FROM_OVERLAY
            )
        }
        merged = secoc.profiles(bus, forged)
        assert merged[CMD_PDU].authenticated is True
        assert merged[CMD_PDU].source == secoc.FROM_ARXML

    def test_overlay_fills_what_arxml_omits(self, bus, overlay_path):
        merged = secoc.profiles(bus, overlay_path)
        assert merged[CMD_PDU].source == secoc.FROM_ARXML
        assert merged[DIAG_PDU].source == secoc.FROM_OVERLAY


class TestAnnotate:
    def test_edge_unions_both_endpoint_ports(self, bus, build):
        """Only the sender port is mapped, so the union is what finds the PDUs."""
        g = secoc.annotate(build(bus), bus)
        attrs = next(iter(g[HEAD][GW].values()))
        assert attrs["bus_visible"] is True
        assert set(attrs["pdus"]) == {CMD_PDU, DIAG_PDU}

    def test_mixed_pdus_make_the_edge_unauthenticated(self, bus, build):
        """Cmd is protected, Diag is not; the edge as a whole is not protected."""
        g = secoc.annotate(build(bus), bus)
        attrs = next(iter(g[HEAD][GW].values()))
        assert attrs["authenticated"] is False
        assert attrs["unprotected_pdus"] == (DIAG_PDU,)

    def test_fully_protected_edge_reports_true(self, bus, build):
        protected = secoc.profiles(bus)
        protected[DIAG_PDU] = secoc.SecOcProfile(
            pdu=DIAG_PDU, authenticated=True, source=secoc.FROM_OVERLAY
        )
        g = secoc.annotate(build(bus), bus, protected)
        attrs = next(iter(g[HEAD][GW].values()))
        assert attrs["authenticated"] is True
        assert attrs["unprotected_pdus"] == ()


class TestNotApplicableVersusMissing:
    def test_internal_connector_is_none_not_false(self, real, build):
        """Every connector in the upstream ECU extract is RTE-internal."""
        g = secoc.annotate(build(real), real)
        internal = [
            d
            for _, _, d in g.edges(data=True)
            if d["connector_kind"] == "ASSEMBLY"
        ]
        assert internal
        assert all(d["authenticated"] is None for d in internal)
        assert all(d["bus_visible"] is False for d in internal)

    def test_no_findings_for_an_all_internal_snapshot(self, real, build):
        """The discriminator working: nothing to report, rather than everything."""
        g = secoc.annotate(build(real), real)
        assert secoc.unprotected_edges(g) == []

    def test_bus_visible_boundary_edge_is_reported(self, bus, build):
        g = secoc.annotate(build(bus), bus)
        findings = secoc.unprotected_edges(g)
        assert len(findings) == 1
        u, v, _ = findings[0]
        assert (u, v) == (HEAD, GW)

    def test_source_recorded_so_evidence_and_assumption_stay_separable(
        self, bus, build
    ):
        g = secoc.annotate(build(bus), bus)
        attrs = next(iter(g[HEAD][GW].values()))
        assert attrs["secoc_source"] in (secoc.FROM_ARXML, secoc.FROM_OVERLAY)
