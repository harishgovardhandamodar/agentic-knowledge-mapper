"""Reproducibility manifests (app.repro).

A stored fingerprint must make a result reproducible: same fingerprint implies
identical inputs/seeds/versions, and a different one must name the party that
changed. These tests pin both directions and the privacy property that inputs
are hashed, not stored.
"""
import json
import unittest

from app import repro as R


class TestFingerprint(unittest.TestCase):
    def test_deterministic_regardless_of_key_order(self):
        self.assertEqual(R.fingerprint({"a": 1, "b": 2}),
                         R.fingerprint({"b": 2, "a": 1}))

    def test_changes_with_content(self):
        self.assertNotEqual(R.fingerprint({"a": 1}), R.fingerprint({"a": 2}))

    def test_input_hashing_hides_content(self):
        self.assertNotEqual(R.hash_input("secret"),
                            R.hash_input("other"))
        self.assertEqual(len(R.hash_input("secret")), 16)

    def test_non_string_inputs_are_canonicalised(self):
        self.assertEqual(R.hash_input({"x": [1, 2]}),
                         R.hash_input({"x": [1, 2]}))


class TestManifest(unittest.TestCase):
    def test_same_inputs_same_fingerprint(self):
        a = R.manifest(inputs={"source": "hello"}, seeds={"mc": 1729},
                       versions={"threat_pack": "1"})
        b = R.manifest(inputs={"source": "hello"}, seeds={"mc": 1729},
                       versions={"threat_pack": "1"})
        self.assertEqual(a["fingerprint"], b["fingerprint"])

    def test_input_content_is_not_stored(self):
        m = R.manifest(inputs={"source": "the secret phrase"})
        blob = json.dumps(m)
        self.assertNotIn("the secret phrase", blob)

    def test_environment_carries_python_and_version(self):
        env = R.manifest()["environment"]
        self.assertTrue(env["python"])
        self.assertEqual(env["manifest_version"], R.MANIFEST_VERSION)

    def test_label_is_kept(self):
        self.assertEqual(R.manifest(label="run-7")["label"], "run-7")


class TestVerifyAndDiff(unittest.TestCase):
    def test_verify_accepts_a_fresh_manifest(self):
        self.assertTrue(R.verify(R.manifest(inputs={"x": "y"})))

    def test_verify_rejects_tampering(self):
        m = R.manifest(inputs={"x": "y"})
        m["seeds"]["mc"] = 999
        self.assertFalse(R.verify(m))

    def test_diff_names_the_changed_section(self):
        a = R.manifest(inputs={"source": "one"}, seeds={"mc": 1})
        b = R.manifest(inputs={"source": "two"}, seeds={"mc": 1})
        d = R.diff(a, b)
        self.assertFalse(d["same"])
        self.assertEqual(d["changed"], ["inputs"])

    def test_diff_of_identical_manifests_is_empty(self):
        a = R.manifest(inputs={"source": "same"})
        d = R.diff(a, R.manifest(inputs={"source": "same"}))
        self.assertTrue(d["same"])
        self.assertEqual(d["changed"], [])

    def test_a_changed_version_is_reported(self):
        a = R.manifest(versions={"threat_pack": "1"})
        b = R.manifest(versions={"threat_pack": "2"})
        self.assertEqual(R.diff(a, b)["changed"], ["versions"])


if __name__ == "__main__":
    unittest.main()
