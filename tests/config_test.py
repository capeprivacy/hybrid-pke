import hybrid_pke
from absl.testing import parameterized


class TestConfig(parameterized.TestCase):
    def test_default_config(self):
        hpke = hybrid_pke.default()
        assert hpke.mode == hybrid_pke.Mode.BASE
        assert hpke.kem == hybrid_pke.Kem.DHKEM_X25519
        assert hpke.kdf == hybrid_pke.Kdf.HKDF_SHA256
        assert hpke.aead == hybrid_pke.Aead.CHACHA20_POLY1305

    def test_config_construct(self):
        mode = hybrid_pke.Mode.BASE
        kem = hybrid_pke.Kem.DHKEM_X25519
        kdf = hybrid_pke.Kdf.HKDF_SHA256
        aead = hybrid_pke.Aead.CHACHA20_POLY1305
        hpke = hybrid_pke.Hpke(mode, kem, kdf, aead)
        assert hpke.mode == mode
        assert hpke.kem == kem
        assert hpke.kdf == kdf
        assert hpke.aead == aead

    @parameterized.parameters(
        {"enum_type": ty, "variants": vrs}
        for ty, vrs in [
            (hybrid_pke.Mode, ["BASE", "PSK", "AUTH", "AUTH_PSK"]),
            (
                hybrid_pke.Kem,
                [
                    "DHKEM_P256",
                    "DHKEM_P384",
                    "DHKEM_P521",
                    "DHKEM_X25519",
                    "DHKEM_X448",
                ],
            ),
            (hybrid_pke.Kdf, ["HKDF_SHA256", "HKDF_SHA384", "HKDF_SHA512"]),
            (
                hybrid_pke.Aead,
                ["AES_128_GCM", "AES_256_GCM", "CHACHA20_POLY1305", "HPKE_EXPORT"],
            ),
        ]
    )
    def test_config_enums(self, enum_type, variants):
        for var in variants:
            enum_variant = getattr(enum_type, var)
            assert isinstance(enum_variant, enum_type)
