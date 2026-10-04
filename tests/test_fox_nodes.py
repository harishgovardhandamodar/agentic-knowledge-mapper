"""Fox-services nodes: declared posture (trust boundary, hardware) and status.

The registry is configuration, so the tests assert the contract rather than
the exact host values: the three nodes exist, each declares a trust boundary
and a data tier, and status probing never raises -- a down or unreachable node
is data, and an unconfigured probe target is ``unprobed``, never a guess.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.gettempdir(), "akm_test_fox_nodes.db"))

from fastapi.testclient import TestClient
from app.main import app as fastapi_app

from app import fox_nodes as F

NODE_IDS = {"axiom", "axiom-dgx", "harishs-macbook-pro"}


class RegistryCase(unittest.TestCase):
    def test_the_three_declared_nodes_exist_with_posture(self):
        self.assertEqual({n["id"] for n in F.FOX_NODES}, NODE_IDS)
        for n in F.FOX_NODES:
            self.assertTrue(n["trust_boundary"])
            self.assertTrue(n["max_data_tier"])
            self.assertIn("role", n)

    def test_axiom_is_the_managed_inference_host(self):
        axiom = next(n for n in F.FOX_NODES if n["id"] == "axiom")
        self.assertIn("data-governance perimeter", axiom["trust_boundary"])
        self.assertEqual(axiom["probe"], "broker")
        self.assertTrue(axiom["gpu"])

    def test_mac_is_outside_the_perimeter_and_limited_to_public(self):
        mac = next(n for n in F.FOX_NODES if n["id"] == "harishs-macbook-pro")
        self.assertIn("outside the perimeter", mac["trust_boundary"])
        self.assertEqual(mac["max_data_tier"], "public")
        self.assertEqual(mac["probe"], "gateway")

    def test_operator_specs_override_the_registry(self):
        with mock.patch.dict(os.environ, {
            "FOX_NODES_SPECS": json.dumps({
                "axiom": {"gpu": "4x RTX 6000 Ada", "ram": "512 GB"}})}):
            # _env_specs is read at import; reload the module to pick it up.
            import importlib
            mod = importlib.reload(F)
        try:
            axiom = next(n for n in mod.FOX_NODES if n["id"] == "axiom")
            self.assertEqual(axiom["gpu"], "4x RTX 6000 Ada")
            self.assertEqual(axiom["ram"], "512 GB")
        finally:
            importlib.reload(F)  # restore the module defaults for later tests


class StatusCase(unittest.TestCase):
    @mock.patch("app.fox_nodes.httpx.get")
    @mock.patch("app.fox_nodes.osh.broker_status")
    def test_broker_down_is_data_not_an_error(self, broker, httpx_get):
        broker.return_value = {"reachable": False, "error": "Timeout"}
        httpx_get.side_effect = Exception("connection refused")
        info = F.infrastructure(timeout=1.0)
        nodes = {n["id"]: n for n in info["nodes"]}
        self.assertEqual(nodes["axiom"]["status"]["state"], "down")
        self.assertIn("Timeout", nodes["axiom"]["status"]["error"])
        # an unconfigured node is unprobed, not down
        self.assertEqual(nodes["axiom-dgx"]["status"]["state"], "unprobed")
        self.assertIn("no probe endpoint", nodes["axiom-dgx"]["status"]["error"])

    @mock.patch("app.fox_nodes.httpx.get")
    @mock.patch("app.fox_nodes.osh.broker_status")
    def test_broker_up_reports_gateway_and_models(self, broker, httpx_get):
        broker.return_value = {"reachable": True,
                               "gateway": {"reachable": True},
                               "sandboxes": [{"name": "s1"}]}
        httpx_get.return_value = mock.Mock(status_code=200,
                                           json=lambda: {"data": [
                                               {"id": "qwen3.8:27b"}]})
        info = F.infrastructure(timeout=1.0)
        nodes = {n["id"]: n for n in info["nodes"]}
        st = nodes["axiom"]["status"]
        self.assertEqual(st["state"], "up")
        self.assertEqual(st["models"], ["qwen3.8:27b"])
        self.assertEqual(len(st["sandboxes"]), 1)


class EndpointCase(unittest.TestCase):
    def test_infrastructure_endpoint_returns_the_nodes(self):
        with mock.patch("app.fox_nodes.osh.broker_status") as broker, \
             mock.patch("app.fox_nodes.httpx.get") as httpx_get:
            broker.return_value = {"reachable": True,
                                   "gateway": {"reachable": True},
                                   "sandboxes": []}
            httpx_get.side_effect = Exception("offline")
            with TestClient(fastapi_app) as c:
                r = c.get("/api/leadership/infrastructure")
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertEqual({n["id"] for n in d["nodes"]}, NODE_IDS)
        self.assertIn("note", d)


if __name__ == "__main__":
    unittest.main()