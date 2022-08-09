from absl.testing import parameterized

import hybrid_pke


class TestHpke(parameterized.TestCase):
    def test_hpke_seal(self):
        pk = b"my fake public key is 32 bytes !"
        ptxt = b"hello, my name is Vincent Law"
        hpke = hybrid_pke.default_config()
        info = b""
        aad = b""
        encap, ciphertext = hpke.seal(pk, info, aad, ptxt)
        # 32 bytes (KEM-derived public key) + 45 bytes (ciphertext of ptxt) = 77 bytes
        assert len(encap) == 32
        assert len(ciphertext) == 45

    def test_wrong_pk_size(self):
        pk = b"my fake public key is greater than 32 bytes !"
        ptxt = b"hello, my name is Vincent Law"
        hpke = hybrid_pke.default_config()
        info = b""
        aad = b""
        with self.assertRaises(hybrid_pke.errors.CryptoError):
            _, _ = hpke.seal(pk, info, aad, ptxt)

    def test_hpke_onetrip(self):
        hpke = hybrid_pke.default_config()
        skR, pkR = hpke.generate_key_pair()
        ptxt = b"my name is Vincent Law"
        info = b""
        aad = b""
        encap, ctxt = hpke.seal(pkR, info, aad, ptxt)
        ptxt_roundtrip = hpke.open(encap, skR, info, aad, ctxt)
        assert ptxt == ptxt_roundtrip

    @parameterized.parameters(
        hybrid_pke.Kem.DHKEM_P384,
        hybrid_pke.Kem.DHKEM_P521,
        hybrid_pke.Kem.DHKEM_X448,
    )
    def test_unsupported_keygen(self, kem):
        hpke = hybrid_pke.default_config()
        hpke.kem = kem
        with self.assertRaises(hybrid_pke.errors.CryptoError):
            _, _ = hpke.generate_key_pair()

    @parameterized.parameters(
        (hybrid_pke.Kem.DHKEM_P256, 32, 65),
        (hybrid_pke.Kem.DHKEM_X25519, 32, 32),
    )
    def test_supported_keygen(self, kem, sk_len, pk_len):
        hpke = hybrid_pke.default_config()
        hpke.kem = kem
        sk, pk = hpke.generate_key_pair()
        assert len(sk) == sk_len
        assert len(pk) == pk_len


class TestHpkeConfig(parameterized.TestCase):
    def test_default_config(self):
        hpke = hybrid_pke.default_config()
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
