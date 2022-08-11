import hybrid_pke
from absl.testing import parameterized


class TestHpke(parameterized.TestCase):
    def test_hpke_seal(self):
        pk = b"my fake public key is 32 bytes !"
        ptxt = b"hello, my name is Vincent Law"
        hpke = hybrid_pke.default()
        info = b""
        aad = b""
        encap, ciphertext = hpke.seal(pk, info, aad, ptxt)
        # 32 bytes (KEM-derived public key) + 45 bytes (ciphertext of ptxt) = 77 bytes
        assert len(encap) == 32
        assert len(ciphertext) == 45

    def test_wrong_pk_size(self):
        pk = b"my fake public key is greater than 32 bytes !"
        ptxt = b"hello, my name is Vincent Law"
        hpke = hybrid_pke.default()
        info = b""
        aad = b""
        with self.assertRaises(hybrid_pke.errors.CryptoError):
            _, _ = hpke.seal(pk, info, aad, ptxt)

    def test_hpke_onetrip(self):
        hpke = hybrid_pke.default()
        skR, pkR = hpke.generate_key_pair()
        ptxt = b"my name is Vincent Law"
        info = b""
        aad = b""
        encap, ctxt = hpke.seal(pkR, info, aad, ptxt)
        ptxt_onetrip = hpke.open(encap, skR, info, aad, ctxt)
        assert ptxt == ptxt_onetrip

    @parameterized.parameters(
        hybrid_pke.Kem.DHKEM_P384,
        hybrid_pke.Kem.DHKEM_P521,
        hybrid_pke.Kem.DHKEM_X448,
    )
    def test_unsupported_keygen(self, kem):
        hpke = hybrid_pke.default(kem=kem)
        with self.assertRaises(hybrid_pke.errors.CryptoError):
            _, _ = hpke.generate_key_pair()

    @parameterized.parameters(
        (hybrid_pke.Kem.DHKEM_P256, 32, 65),
        (hybrid_pke.Kem.DHKEM_X25519, 32, 32),
    )
    def test_supported_keygen(self, kem, sk_len, pk_len):
        hpke = hybrid_pke.default(kem=kem)
        sk, pk = hpke.generate_key_pair()
        assert len(sk) == sk_len
        assert len(pk) == pk_len

    def test_exporter_secret(self):
        exporter_context = b"mock exporter context"
        exporter_secret_length = 64
        hpke = hybrid_pke.default()
        skR, pkR = hpke.generate_key_pair()
        info = b""
        encap, sender_exporter = hpke.send_export(
            pkR, info, exporter_context, exporter_secret_length
        )
        receiver_exporter = hpke.receiver_export(
            encap, skR, info, exporter_context, exporter_secret_length
        )
        assert sender_exporter == receiver_exporter

    def test_key_schedule(self):
        exporter_context = b"mock exporter context"
        exporter_secret_length = 64
        hpke = hybrid_pke.default()
        _, pkR = hpke.generate_key_pair()
        info = b""
        _, shared_secret = hpke.send_export(
            pkR, info, exporter_context, exporter_secret_length
        )

        context = hpke.key_schedule(shared_secret, info, psk=None, psk_id=None)

        aad = b""
        ptxt = b"my name is Vincent Law"
        _ = context.seal(aad, ptxt)

    @parameterized.parameters(
        (None, bytes.fromhex("1541a60d09ebc96c")),
        (bytes.fromhex("1541a60d09ebc96c"), None),
        (b"", None),
        (None, b""),
    )
    def test_key_schedule_args_raise(self, psk, psk_id):
        exporter_context = b"mock exporter context"
        exporter_secret_length = 64
        hpke = hybrid_pke.default()
        _, pkR = hpke.generate_key_pair()
        info = b""
        _, shared_secret = hpke.send_export(
            pkR, info, exporter_context, exporter_secret_length
        )

        with self.assertRaises(ValueError):
            _ = hpke.key_schedule(shared_secret, info, psk=psk, psk_id=psk_id)
