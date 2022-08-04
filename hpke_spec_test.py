from absl.testing import parameterized

import hpke


class TestHpkeSpec(parameterized.TestCase):
    def test_hpke_seal(self):
        pk = b"my fake public key is 32 bytes !"
        ptxt = b"hello, my name is Vincent Law"
        cfg = hpke.default_config()
        info = b""
        aad = b""
        encap, ciphertext = cfg.seal(pk, info, aad, ptxt, psk=None, psk_id=None, sk_s=None)
        # 32 bytes (KEM-derived public key) + 45 bytes (ciphertext of ptxt) = 77 bytes
        assert len(encap) == 32
        assert len(ciphertext) == 45

    def test_wrong_pk_size(self):
        pk = b"my fake public key is greater than 32 bytes !"
        ptxt = b"hello, my name is Vincent Law"
        cfg = hpke.default_config()
        info = b""
        aad = b""
        with self.assertRaises(hpke.errors.CryptoError):
            _, _ = cfg.seal(pk, info, aad, ptxt, psk=None, psk_id=None, sk_s=None)

    def test_hpke_roundtrip(self):
        cfg = hpke.default_config()
        skR, pkR = cfg.generate_key_pair()
        skS, pkS = cfg.generate_key_pair()
        ptxt = b"my name is Vincent Law"
        info = b""
        aad = b""
        encap, ctxt = cfg.seal(pkR, info, aad, ptxt, psk=None, psk_id=None, sk_s=None)
        ptxt_roundtrip = cfg.open(encap, skR, info, aad, ctxt, psk=None, psk_id=None, pk_s=None)
        assert ptxt == ptxt_roundtrip

    @parameterized.parameters(
        hpke.Kem.DHKEM_P384,
        hpke.Kem.DHKEM_P521,
        hpke.Kem.DHKEM_X448,
    )
    def test_unsupported_keygen(self, kem):
        cfg = hpke.default_config()
        cfg.kem = kem
        with self.assertRaises(hpke.errors.CryptoError):
            _, _ = cfg.generate_key_pair()

    @parameterized.parameters(
        (hpke.Kem.DHKEM_P256, 32, 65),
        (hpke.Kem.DHKEM_X25519, 32, 32),
    )
    def test_supported_keygen(self, kem, sk_len, pk_len):
        cfg = hpke.default_config()
        cfg.kem = kem
        sk, pk = cfg.generate_key_pair()
        assert len(sk) == sk_len
        assert len(pk) == pk_len


class TestHpkeConfig(parameterized.TestCase):
    def test_default_config(self):
        cfg = hpke.default_config()
        assert cfg.mode == hpke.Mode.BASE
        assert cfg.kem == hpke.Kem.DHKEM_X25519
        assert cfg.kdf == hpke.Kdf.HKDF_SHA256
        assert cfg.aead == hpke.Aead.CHACHA20_POLY1305

    def test_config_construct(self):
        mode = hpke.Mode.BASE
        kem = hpke.Kem.DHKEM_X25519
        kdf = hpke.Kdf.HKDF_SHA256
        aead = hpke.Aead.CHACHA20_POLY1305
        cfg = hpke.Hpke(mode, kem, kdf, aead)
        assert cfg.mode == mode
        assert cfg.kem == kem
        assert cfg.kdf == kdf
        assert cfg.aead == aead

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
