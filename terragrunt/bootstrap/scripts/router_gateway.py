#!/usr/bin/env python3
"""Attach/detach a Neutron router gateway with retries for OVH API failures."""

import argparse
import os
import sys
import time
from typing import Any

import openstack
from openstack.exceptions import ConfigException, HttpException, ResourceNotFound, SDKException

RETRIES = 6
RETRYABLE_HTTP_STATUSES = {408, 409, 429, 500, 502, 503, 504}


def gateway_network(connection: Any, router_id: str) -> str | None:
    """Get the current external network UUID, distinguishing a missing router."""
    router = connection.network.get_router(router_id)
    if router is None:
        raise ResourceNotFound(f"Router {router_id} not found")
    gateway = router.external_gateway_info or {}
    return gateway.get("network_id")


def main(action: str, connection: Any = None) -> None:
    router_id = os.environ["ROUTER_ID"]
    network_id = os.environ["NETWORK_ID"]
    connection = connection if connection is not None else openstack.connect()
    desired = network_id if action == "attach" else None

    for attempt in range(1, RETRIES + 1):
        try:
            current = gateway_network(connection, router_id)
            if current == desired:
                print(f"Router {router_id}: gateway {action} verified")
                return
            if current is not None and current != network_id:
                raise RuntimeError(f"Router {router_id} uses unexpected gateway {current}")

            external_gateway_info = {"network_id": network_id} if action == "attach" else None
            connection.network.update_router(router_id, external_gateway_info=external_gateway_info)
        except ResourceNotFound:
            if action == "detach":
                print(f"Router {router_id}: already deleted")
                return
            raise
        except SDKException as exc:
            if isinstance(exc, ConfigException):
                raise
            if isinstance(exc, HttpException) and exc.status_code not in RETRYABLE_HTTP_STATUSES:
                raise
            print(f"Gateway {action} attempt {attempt}: {exc}", file=sys.stderr)

        if attempt < RETRIES:
            time.sleep(5 * attempt)

    try:
        verified = gateway_network(connection, router_id)
    except ResourceNotFound:
        if action == "detach":
            print(f"Router {router_id}: already deleted")
            return
        raise
    if verified != desired:
        raise RuntimeError(
            f"Router {router_id}: gateway {action} not confirmed after {RETRIES} attempts"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("attach", "detach"))
    main(parser.parse_args().action)
