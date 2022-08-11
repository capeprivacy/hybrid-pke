import dataclasses
from typing import List
from typing import Optional

import hybrid_pke

INT_TO_MODE = {
    0: hybrid_pke.Mode.BASE,
    1: hybrid_pke.Mode.PSK,
    2: hybrid_pke.Mode.AUTH,
    3: hybrid_pke.Mode.AUTH_PSK,
}
INT_TO_KEM = {
    16: hybrid_pke.Kem.DHKEM_P256,
    17: hybrid_pke.Kem.DHKEM_P384,
    18: hybrid_pke.Kem.DHKEM_P521,
    32: hybrid_pke.Kem.DHKEM_X25519,
    33: hybrid_pke.Kem.DHKEM_X448,
}
INT_TO_KDF = {
    1: hybrid_pke.Kdf.HKDF_SHA256,
    2: hybrid_pke.Kdf.HKDF_SHA384,
    3: hybrid_pke.Kdf.HKDF_SHA512,
}
INT_TO_AEAD = {
    1: hybrid_pke.Aead.AES_128_GCM,
    2: hybrid_pke.Aead.AES_256_GCM,
    3: hybrid_pke.Aead.CHACHA20_POLY1305,
    65535: hybrid_pke.Aead.HPKE_EXPORT,
}


class ExpectedFailureMode(Exception):
    """Exception denoting an HPKE config that is known to fail test vector suite."""

    pass


@dataclasses.dataclass
class Setup:
    mode: hybrid_pke.Mode
    kem: hybrid_pke.Kem
    kdf: hybrid_pke.Kdf
    aead: hybrid_pke.Aead
    info: bytes
    ikmR: bytes
    ikmS: Optional[bytes]
    ikmE: bytes
    skRm: bytes
    skSm: Optional[bytes]
    skEm: bytes
    psk: Optional[bytes]
    psk_id: Optional[bytes]
    pkRm: bytes
    pkSm: Optional[bytes]
    pkEm: bytes
    enc: bytes
    shared_secret: bytes
    key_schedule_context: bytes
    secret: bytes
    key: bytes
    base_nonce: bytes
    exporter_secret: bytes

    @classmethod
    def from_json_dict(cls, json_dict):
        kwargs = {}
        kwargs["mode"] = INT_TO_MODE[int(json_dict.pop("mode"))]
        kwargs["kem"] = INT_TO_KEM[int(json_dict.pop("kem_id"))]
        kwargs["kdf"] = INT_TO_KDF[int(json_dict.pop("kdf_id"))]
        kwargs["aead"] = INT_TO_AEAD[int(json_dict.pop("aead_id"))]
        json_dict = {k: bytes.fromhex(v) for k, v in json_dict.items()}
        kwargs.update(json_dict)
        # set optional kwargs to None if missing
        for k in ["ikmS", "skSm", "psk", "psk_id", "pkSm"]:
            kwargs[k] = kwargs.get(k, None)
        return cls(**kwargs)


@dataclasses.dataclass
class Encryption:
    sequence_number: int
    pt: bytes
    aad: bytes
    nonce: bytes
    ct: bytes

    @classmethod
    def from_json_dict(cls, sequence_number, json_dict):
        json_dict = {k: bytes.fromhex(v) for k, v in json_dict.items()}
        return cls(sequence_number=sequence_number, **json_dict)


@dataclasses.dataclass
class Export:
    exporter_context: bytes
    L: int
    exported_value: bytes

    @classmethod
    def from_json_dict(cls, json_dict):
        exporter_context = bytes.fromhex(json_dict["exporter_context"])
        L = int(json_dict["L"])
        exported_value = bytes.fromhex(json_dict["exported_value"])
        return cls(
            exporter_context=exporter_context, L=L, exported_value=exported_value
        )


@dataclasses.dataclass
class KatTestCase:
    setup: Setup
    encryptions: List[Encryption]
    exports: List[Export]

    @classmethod
    def from_json_dict(cls, json_dict):
        encryptions = [
            Encryption.from_json_dict(i, enc)
            for i, enc in enumerate(json_dict.pop("encryptions"))
        ]
        exports = [Export.from_json_dict(ev) for ev in json_dict.pop("exports")]
        setup = Setup.from_json_dict(json_dict)
        return cls(setup=setup, encryptions=encryptions, exports=exports)
