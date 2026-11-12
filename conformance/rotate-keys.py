"""Runs the suite's server key rotation module the way an operator would: once the module has read the server's key
set and waits to be started, rotates the server's signing keys and only then starts it.

The suite's own plan runner starts that module the moment it is configured, leaving no moment to rotate in, so the
module fails there by construction and is run again here. Run from the suite's scripts directory, with
CONFORMANCE_SERVER naming the suite and HOST_ROTATE_URL the conformance host's rotation endpoint.
Usage: python rotate-keys.py <plan name> <plan variant as JSON> <configuration file>
"""
import asyncio
import json
import os
import sys

import httpx

from conformance import Conformance

MODULE = "oidcc-server-rotate-keys"


async def main(plan_name, variant, config_file):
    suite = Conformance(os.environ["CONFORMANCE_SERVER"], None, False)
    await suite.wait_for_server_ready()

    with open(config_file, encoding="utf-8") as f:
        plan = await suite.create_test_plan(plan_name, f.read(), json.loads(variant))

    module = await suite.create_test_from_plan(plan["id"], MODULE)
    module_id = module["id"]
    print(f"Created {MODULE}: {module_id}", flush=True)

    state = await suite.wait_for_state(module_id, ["CONFIGURED", "FINISHED"])
    if state != "CONFIGURED":
        raise SystemExit(f"{MODULE} reached {state} before it could be started")

    async with httpx.AsyncClient(verify=False) as client:
        response = await client.post(os.environ["HOST_ROTATE_URL"])
    if response.status_code != 204:
        raise SystemExit(f"The host refused to rotate its keys: HTTP {response.status_code}")
    print("Rotated the host's signing keys", flush=True)

    await suite.start_test(module_id)
    await suite.wait_for_state(module_id, ["FINISHED"])
    info = await suite.get_module_info(module_id)
    result = info.get("result")
    print(f"{MODULE}: {result}", flush=True)
    await suite.close_client()
    return 0 if result == "PASSED" else 1


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    sys.exit(asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3])))
