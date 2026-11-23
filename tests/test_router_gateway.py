"""Router gateway operations use the OpenStack SDK and handle OVH API failures."""

import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from openstack.exceptions import HttpException, ResourceNotFound

PATH = Path(__file__).resolve().parents[1] / "terragrunt/bootstrap/scripts/router_gateway.py"
SPEC = importlib.util.spec_from_file_location("router_gateway", PATH)
router_gateway = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(router_gateway)

ENV = {"ROUTER_ID": "router-123", "NETWORK_ID": "network-123"}


class RouterGatewayTests(unittest.TestCase):
    def test_attach_updates_gateway_and_verifies(self):
        state = {"gateway": None}
        network = mock.Mock()
        network.get_router.side_effect = lambda _: SimpleNamespace(
            external_gateway_info={"network_id": state["gateway"]} if state["gateway"] else None
        )
        network.update_router.side_effect = lambda _, external_gateway_info: state.update(
            gateway=external_gateway_info["network_id"]
        )
        with mock.patch.dict(os.environ, ENV), mock.patch.object(router_gateway.time, "sleep"):
            router_gateway.main("attach", SimpleNamespace(network=network))
        network.update_router.assert_called_once_with(
            "router-123", external_gateway_info={"network_id": "network-123"}
        )
        self.assertEqual(state["gateway"], "network-123")

    def test_detach_updates_gateway(self):
        network = mock.Mock()
        network.get_router.side_effect = [
            SimpleNamespace(external_gateway_info={"network_id": "network-123"}),
            SimpleNamespace(external_gateway_info=None),
        ]
        with mock.patch.dict(os.environ, ENV), mock.patch.object(router_gateway.time, "sleep"):
            router_gateway.main("detach", SimpleNamespace(network=network))
        network.update_router.assert_called_once_with("router-123", external_gateway_info=None)

    def test_detach_missing_router_succeeds(self):
        network = mock.Mock()
        network.get_router.side_effect = ResourceNotFound("Router not found")
        with mock.patch.dict(os.environ, ENV):
            router_gateway.main("detach", SimpleNamespace(network=network))
        network.update_router.assert_not_called()

    def test_attach_missing_router_fails(self):
        network = mock.Mock()
        network.get_router.side_effect = ResourceNotFound("Router not found")
        with mock.patch.dict(os.environ, ENV):
            with self.assertRaises(ResourceNotFound):
                router_gateway.main("attach", SimpleNamespace(network=network))

    def test_auth_failure_does_not_retry(self):
        network = mock.Mock()
        network.get_router.return_value = SimpleNamespace(external_gateway_info=None)
        unauthorized = HttpException("Unauthorized")
        unauthorized.status_code = 401
        network.update_router.side_effect = unauthorized
        with mock.patch.dict(os.environ, ENV), mock.patch.object(router_gateway.time, "sleep") as sleep:
            with self.assertRaises(HttpException):
                router_gateway.main("attach", SimpleNamespace(network=network))
        network.update_router.assert_called_once()
        sleep.assert_not_called()

    def test_gateway_504_then_success_is_verified(self):
        state = {"gateway": None}
        network = mock.Mock()
        network.get_router.side_effect = lambda _: SimpleNamespace(
            external_gateway_info={"network_id": state["gateway"]} if state["gateway"] else None
        )
        failure = HttpException("Gateway Timeout")
        failure.status_code = 504

        def update(router_id, external_gateway_info):
            state["gateway"] = external_gateway_info["network_id"]
            raise failure

        network.update_router.side_effect = update
        with mock.patch.dict(os.environ, ENV), mock.patch.object(router_gateway.time, "sleep") as sleep:
            router_gateway.main("attach", SimpleNamespace(network=network))
        self.assertEqual(state["gateway"], "network-123")
        network.update_router.assert_called_once()
        sleep.assert_called_once_with(5)


if __name__ == "__main__":
    unittest.main()
