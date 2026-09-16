"""Signal-chain tests: port -> system signal -> I-signal -> PDU.

The chain is the SecOC join key, and its *absence* is the discriminator that keeps
RTE-internal connectors out of the findings list.
"""

from arxml_secdiff import signals

OUT = "/B/Swc/Head/Out"
IN = "/B/Swc/Gw/In"
CMD_PDU = "/B/Comm/CmdIPdu"
DIAG_PDU = "/B/Comm/DiagIPdu"
SECURED_PDU = "/B/Comm/CmdSecuredIPdu"


class TestExtraction:
    def test_counts(self, bus):
        assert len(bus.system_signals) == 3  # Cmd, Diag, Orphan
        assert len(bus.isignals) == 2  # Orphan has none
        assert len(bus.pdus) == 3  # 2 plain I-PDUs + 1 SECURED-I-PDU
        assert len(bus.data_mappings) == 3

    def test_isignal_points_at_its_system_signal(self, bus):
        assert bus.isignals["/B/Comm/CmdISig"].system_signal == "/B/Comm/CmdSSig"

    def test_pdu_collects_its_isignals(self, bus):
        assert bus.pdus[CMD_PDU].isignals == ("/B/Comm/CmdISig",)
        assert bus.pdus[CMD_PDU].kind == "I-SIGNAL-I-PDU"

    def test_secured_pdu_records_its_payload(self, bus):
        secured = bus.pdus[SECURED_PDU]
        assert secured.kind == "SECURED-I-PDU"
        assert secured.payload_ref == CMD_PDU

    def test_data_mapping_keys_on_port_and_data_element(self, bus):
        cmd = next(m for m in bus.data_mappings if m.system_signal == "/B/Comm/CmdSSig")
        assert cmd.port == OUT
        assert cmd.data_prototype == "/B/If/Tel/cmd"
        assert cmd.kind == "SENDER-RECEIVER"

    def test_mapping_may_key_on_a_component_type_port(self, bus):
        """Upstream keys on a composition outer port; this file does not.

        The extractor must not assume either shape.
        """
        assert all(m.port == OUT for m in bus.data_mappings)


class TestRouteResolution:
    def test_full_chain_resolves(self, bus):
        route = next(r for r in bus.routes if r.data_prototype == "/B/If/Tel/cmd")
        assert route.system_signal == "/B/Comm/CmdSSig"
        assert route.isignal == "/B/Comm/CmdISig"
        assert route.pdu == CMD_PDU

    def test_partial_chain_is_kept_not_dropped(self, bus):
        """A signal declared but never placed on a PDU is a real condition."""
        orphan = [r for r in bus.routes if r.system_signal == "/B/Comm/OrphanSSig"]
        assert len(orphan) == 1
        assert orphan[0].isignal is None
        assert orphan[0].pdu is None

    def test_route_count_matches_mappings_here(self, bus):
        assert len(bus.routes) == 3


class TestBusVisibility:
    def test_mapped_port_reaches_its_pdus(self, bus):
        assert signals.pdus_for_port(bus, OUT) == {CMD_PDU, DIAG_PDU}
        assert signals.is_bus_visible(bus, OUT) is True

    def test_orphan_signal_contributes_no_pdu(self, bus):
        """OrphanSSig is mapped from OUT but adds nothing to the PDU set."""
        assert SECURED_PDU not in signals.pdus_for_port(bus, OUT)
        assert len(signals.pdus_for_port(bus, OUT)) == 2

    def test_unmapped_port_is_not_bus_visible(self, bus):
        """Only the sender side is mapped in this fixture.

        The receiving port therefore resolves to no PDU on its own, which is why
        `secoc.annotate` unions both endpoints rather than trusting one.
        """
        assert signals.is_bus_visible(bus, IN) is False

    def test_none_port_is_safe(self, bus):
        assert signals.pdus_for_port(bus, None) == set()
        assert signals.is_bus_visible(bus, None) is False


class TestRealEcuExtract:
    def test_chain_resolves_end_to_end(self, real):
        assert len(real.system_signals) == 4
        assert len(real.isignals) == 4
        assert len(real.pdus) == 4
        assert len(real.routes) == 4
        assert all(r.pdu for r in real.routes)

    def test_boundary_port_is_bus_visible(self, real):
        assert signals.is_bus_visible(real, "/Demo/EDC/EDC/CombinedStatus") is True

    def test_internal_service_port_is_not(self, real):
        """The door command service never leaves the ECU, so SecOC cannot apply."""
        assert signals.is_bus_visible(real, "/Demo/Door/Door/Command") is False

    def test_no_secoc_in_the_upstream_sample(self, real):
        assert not any(p.kind == "SECURED-I-PDU" for p in real.pdus.values())
