import copy
import json
import pathlib

import hybrid_pke
import kat_test_utils as ut
from absl.testing import parameterized

VECTORS_PATH = pathlib.Path(__file__).parent / "test-vectors.json"
with open(VECTORS_PATH, "r") as f:
    vectors_json = json.load(f)
    TEST_VECTORS = [ut.KatTestCase.from_json_dict(vector) for vector in vectors_json]


def _is_expected_failure_mode(hpke):
    if hpke.kem not in [hybrid_pke.Kem.DHKEM_P256, hybrid_pke.Kem.DHKEM_X25519]:
        return True


class TestKat(parameterized.TestCase):
    def _setup_kat_test_case(self, kat):
        setup = kat.setup
        encryptions = kat.encryptions
        exports = kat.exports

        # init Hpke with given mode & ciphersuite
        hpke = hybrid_pke.Hpke(
            mode=setup.mode,
            kem=setup.kem,
            kdf=setup.kdf,
            aead=setup.aead,
        )
        # drop out early if config is unsupported
        if _is_expected_failure_mode(hpke):
            raise NotImplementedError()

        return setup, encryptions, exports, hpke

    @parameterized.parameters(*TEST_VECTORS)
    def test_derive_key_pair(self, kat):
        try:
            setup, encryptions, exports, hpke = self._setup_kat_test_case(kat)
        except NotImplementedError:
            return

        # Test key pair derivation
        my_sk_r, my_pk_r = hpke.derive_key_pair(setup.ikmR)
        assert setup.skRm == my_sk_r
        assert setup.pkRm == my_pk_r
        my_sk_e, my_pk_e = hpke.derive_key_pair(setup.ikmE)
        assert setup.skEm == my_sk_e
        assert setup.pkEm == my_pk_e
        if setup.ikmS is not None:
            my_sk_s, my_pk_s = hpke.derive_key_pair(setup.ikmS)
            assert setup.skSm == my_sk_s
            assert setup.pkSm == my_pk_s

    @parameterized.parameters(*TEST_VECTORS)
    def test_direct_ctx(self, kat):
        try:
            setup, encryptions, exports, hpke = self._setup_kat_test_case(kat)
        except NotImplementedError:
            return

        # Use internal key_schedule function for KAT
        direct_ctx = hpke.key_schedule(
            setup.shared_secret, setup.info, psk=setup.psk, psk_id=setup.psk_id
        )
        # TODO(jvmncs) check internals of ctx:
        # key, nonce, exporter_secret, sequence_number

        # Encrypt
        for i, encryption in enumerate(encryptions):
            # Test KAT seal direct_cctx
            ct = direct_ctx.seal(encryption.aad, encryption.pt)
            assert encryption.ct == ct

        # Test KAT on direct_ctx for exporters
        for i, export in enumerate(exports):
            print(f"Test export {i}...")
            exported_secret = direct_ctx.export(export.exporter_context, export.L)
            assert exported_secret == export.exported_value

    @parameterized.parameters(*TEST_VECTORS)
    def test_single_shot_api(self, kat):
        try:
            setup, encryptions, exports, hpke = self._setup_kat_test_case(kat)
        except NotImplementedError:
            return

        # Encrypt
        for i, encryption in enumerate(encryptions):
            # Refresh hpke
            hpke = copy.deepcopy(hpke)
            print(f"Test encryption {i}...")

            # Test single-shot API
            enc, ct = hpke.seal(
                setup.pkRm,
                setup.info,
                encryption.aad,
                encryption.pt,
                setup.psk,
                setup.psk_id,
                setup.skSm,
            )
            ptxt_out = hpke.open(
                enc,
                setup.skRm,
                setup.info,
                encryption.aad,
                ct,
                setup.psk,
                setup.psk_id,
                setup.pkSm,
            )
            assert ptxt_out == encryption.pt

    @parameterized.parameters(*TEST_VECTORS)
    def test_context_api(self, kat):
        try:
            setup, encryptions, exports, hpke = self._setup_kat_test_case(kat)
        except NotImplementedError:
            return

        # Setup sender & receiver for self tests
        enc, sender_ctx = hpke.setup_sender(
            setup.pkRm,
            setup.info,
            psk=setup.psk,
            psk_id=setup.psk_id,
            sk_s=setup.skSm,
        )
        receiver_ctx = hpke.setup_receiver(
            enc,
            setup.skRm,
            setup.info,
            psk=setup.psk,
            psk_id=setup.psk_id,
            pk_s=setup.pkSm,
        )

        # Encrypt
        for i, encryption in enumerate(encryptions):
            print(f"Test encryption {i}...")

            # Test context API
            ctxt_out = sender_ctx.seal(encryption.aad, encryption.pt)
            ptxt_out = receiver_ctx.open(encryption.aad, ctxt_out)
            assert ptxt_out == encryption.pt

    @parameterized.parameters(*TEST_VECTORS)
    def test_kat(self, kat):
        try:
            setup, encryptions, exports, hpke = self._setup_kat_test_case(kat)
        except NotImplementedError:
            return

        # Setup KAT receiver
        receiver_ctx_kat = hpke.setup_receiver(
            setup.enc,
            setup.skRm,
            setup.info,
            psk=setup.psk,
            psk_id=setup.psk_id,
            pk_s=setup.pkSm,
        )
        # NOTE(jvmncs) hard to check ctx internals the way we do above;
        # requires seeding the hpke so that encap of sender context will
        # match the kat_enc from the test vector, e.g. as in
        # https://github.com/franziskuskiefer/hpke-rs/blob/main/tests/test_hpke_kat.rs#L167

        # Encrypt
        for encryption in encryptions:
            # Test KAT receiver context open
            ptxt_out = receiver_ctx_kat.open(encryption.aad, encryption.ct)
            assert ptxt_out == encryption.pt
