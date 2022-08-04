from absl.testing import parameterized

import hpke_spec as hpke


class TestHpkeSpec(parameterized.TestCase):
    def test_hpke_seal(self):
        pk = b"my fake public key is 32 bytes !"
        ptxt = b"hello, my name is Vincent Law"
        config = hpke.default_config()
        ciphertext = hpke.seal(pk, ptxt, config)
        # 32 bytes (KEM-derived public key) + 45 bytes (ciphertext of ptxt) = 77 bytes
        assert len(ciphertext) == 77

    def test_wrong_pk_size(self):
        try:
            pk = b"my fake public key is greater than 32 bytes !"
            ptxt = b"hello, my name is Vincent Law"
            config = hpke.default_config()
            _ = hpke.seal(pk, ptxt, config)
        except:  # noqa: E722
            # the exception type is pyo3_runtime.PanicException,
            # which isn't accessible from Python.
            return
        raise AssertionError(
            "hpke_seal failed to raise Exception on malformed public key"
        )

    def test_hpke_roundtrip(self):
        config = hpke.default_config()
        skR, pkR = hpke.generate_keypair(kem=config.kem)
        ptxt = b"my name is Vincent Law"
        ctxt = hpke.seal(pkR, ptxt, config)
        ptxt_roundtrip = hpke.open(skR, ctxt, config)
        assert ptxt == ptxt_roundtrip

    @parameterized.parameters(
        hpke.KEM.DHKEM_P384_HKDF_SHA384,
        hpke.KEM.DHKEM_P521_HKDF_SHA512,
        hpke.KEM.DHKEM_X448_HKDF_SHA512,
    )
    def test_unsupported_keygen(self, kem):
        with self.assertRaises(RuntimeError):
            _, _ = hpke.generate_keypair(kem)

    @parameterized.parameters(
        (hpke.KEM.DHKEM_P256_HKDF_SHA256, 32, 65),
        (hpke.KEM.DHKEM_X25519_HKDF_SHA256, 32, 32),
    )
    def test_supported_keygen(self, kem, sk_len, pk_len):
        sk, pk = hpke.generate_keypair(kem)
        assert len(sk) == sk_len
        assert len(pk) == pk_len


class TestHpkeConfig(parameterized.TestCase):
    def test_default_config(self):
        config = hpke.default_config()
        assert config.mode == hpke.Mode.mode_base
        assert config.kem == hpke.KEM.DHKEM_X25519_HKDF_SHA256
        assert config.kdf == hpke.KDF.HKDF_SHA256
        assert config.aead == hpke.AEAD.ChaCha20Poly1305

    def test_config_construct(self):
        mode = hpke.Mode.mode_base
        kem = hpke.KEM.DHKEM_X25519_HKDF_SHA256
        kdf = hpke.KDF.HKDF_SHA256
        aead = hpke.AEAD.ChaCha20Poly1305
        config = hpke.HPKEConfig(mode, kem, kdf, aead)
        assert config.mode == mode
        assert config.kem == kem
        assert config.kdf == kdf
        assert config.aead == aead

    @parameterized.parameters(
        {"enum_type": ty, "variants": vrs}
        for ty, vrs in [
            (hpke.Mode, ["mode_base", "mode_psk", "mode_auth", "mode_auth_psk"]),
            (
                hpke.KEM,
                [
                    "DHKEM_P256_HKDF_SHA256",
                    "DHKEM_P384_HKDF_SHA384",
                    "DHKEM_P521_HKDF_SHA512",
                    "DHKEM_X25519_HKDF_SHA256",
                    "DHKEM_X448_HKDF_SHA512",
                ],
            ),
            (hpke.KDF, ["HKDF_SHA256", "HKDF_SHA384", "HKDF_SHA512"]),
            (
                hpke.AEAD,
                ["AES_128_GCM", "AES_256_GCM", "ChaCha20Poly1305", "Export_only"],
            ),
        ]
    )
    def test_config_enums(self, enum_type, variants):
        for var in variants:
            enum_variant = getattr(enum_type, var)
            assert isinstance(enum_variant, enum_type)
