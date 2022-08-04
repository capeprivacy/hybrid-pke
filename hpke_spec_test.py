from absl.testing import parameterized

import hpke


# class TestHpkeSpec(parameterized.TestCase):
#     def test_hpke_seal(self):
#         pk = b"my fake public key is 32 bytes !"
#         ptxt = b"hello, my name is Vincent Law"
#         config = hpke.default_config()
#         ciphertext = hpke.seal(pk, ptxt, config)
#         # 32 bytes (KEM-derived public key) + 45 bytes (ciphertext of ptxt) = 77 bytes
#         assert len(ciphertext) == 77

#     def test_wrong_pk_size(self):
#         try:
#             pk = b"my fake public key is greater than 32 bytes !"
#             ptxt = b"hello, my name is Vincent Law"
#             config = hpke.default_config()
#             _ = hpke.seal(pk, ptxt, config)
#         except:  # noqa: E722
#             # the exception type is pyo3_runtime.PanicException,
#             # which isn't accessible from Python.
#             return
#         raise AssertionError(
#             "hpke_seal failed to raise Exception on malformed public key"
#         )

#     def test_hpke_roundtrip(self):
#         config = hpke.default_config()
#         skR, pkR = hpke.generate_keypair(kem=config.kem)
#         ptxt = b"my name is Vincent Law"
#         ctxt = hpke.seal(pkR, ptxt, config)
#         ptxt_roundtrip = hpke.open(skR, ctxt, config)
#         assert ptxt == ptxt_roundtrip

#     @parameterized.parameters(
#         hpke.KEM.DHKEM_P384_HKDF_SHA384,
#         hpke.KEM.DHKEM_P521_HKDF_SHA512,
#         hpke.KEM.DHKEM_X448_HKDF_SHA512,
#     )
#     def test_unsupported_keygen(self, kem):
#         with self.assertRaises(RuntimeError):
#             _, _ = hpke.generate_keypair(kem)

#     @parameterized.parameters(
#         (hpke.KEM.DHKEM_P256_HKDF_SHA256, 32, 65),
#         (hpke.KEM.DHKEM_X25519_HKDF_SHA256, 32, 32),
#     )
#     def test_supported_keygen(self, kem, sk_len, pk_len):
#         sk, pk = hpke.generate_keypair(kem)
#         assert len(sk) == sk_len
#         assert len(pk) == pk_len


class TestHpkeConfig(parameterized.TestCase):
    def test_default_config(self):
        hpke_cfg = hpke.default_config()
        assert hpke_cfg.mode == hpke.Mode.BASE
        assert hpke_cfg.kem == hpke.Kem.DHKEM_X25519
        assert hpke_cfg.kdf == hpke.Kdf.HKDF_SHA256
        assert hpke_cfg.aead == hpke.Aead.CHACHA20_POLY1305

    def test_config_construct(self):
        mode = hpke.Mode.BASE
        kem = hpke.Kem.DHKEM_X25519
        kdf = hpke.Kdf.HKDF_SHA256
        aead = hpke.Aead.CHACHA20_POLY1305
        hpke_cfg = hpke.Hpke(mode, kem, kdf, aead)
        assert hpke_cfg.mode == mode
        assert hpke_cfg.kem == kem
        assert hpke_cfg.kdf == kdf
        assert hpke_cfg.aead == aead

    @parameterized.parameters(
        {"enum_type": ty, "variants": vrs}
        for ty, vrs in [
            (hpke.Mode, ["BASE", "PSK", "AUTH", "AUTH_PSK"]),
            (
                hpke.Kem,
                [
                    "DHKEM_P256",
                    "DHKEM_P384",
                    "DHKEM_P521",
                    "DHKEM_X25519",
                    "DHKEM_X448",
                ],
            ),
            (hpke.Kdf, ["HKDF_SHA256", "HKDF_SHA384", "HKDF_SHA512"]),
            (
                hpke.Aead,
                ["AES_128_GCM", "AES_256_GCM", "CHACHA20_POLY1305", "HPKE_EXPORT"],
            ),
        ]
    )
    def test_config_enums(self, enum_type, variants):
        for var in variants:
            enum_variant = getattr(enum_type, var)
            assert isinstance(enum_variant, enum_type)
