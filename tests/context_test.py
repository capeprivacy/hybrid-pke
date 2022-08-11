import hybrid_pke
from absl.testing import parameterized


class TestContext(parameterized.TestCase):
    def test_repeat_onetrip(self):
        ptxt = b"my name is Vincent Law"
        hpke = hybrid_pke.default()
        skR, pkR = hpke.generate_key_pair()
        info = b""
        aad = b""
        encap, sender_context = hpke.setup_sender(pkR, info)
        receiver_context = hpke.setup_receiver(encap, skR, info)
        for _ in range(17):
            ctxt = sender_context.seal(aad, ptxt)
            ptxt_onetrip = receiver_context.open(aad, ctxt)
            assert ptxt == ptxt_onetrip

    def test_exporter(self):
        exporter_context = b"mock exporter context"
        exporter_secret_length = 64
        hpke = hybrid_pke.default()
        skR, pkR = hpke.generate_key_pair()
        info = b""
        encap, sender_context = hpke.setup_sender(pkR, info)
        receiver_context = hpke.setup_receiver(encap, skR, info)
        sender_exporter_secret = sender_context.export(
            exporter_context, exporter_secret_length
        )
        receiver_exporter_secret = receiver_context.export(
            exporter_context, exporter_secret_length
        )
        assert sender_exporter_secret == receiver_exporter_secret
