"""Runs the suite's server key rotation module the way an operator would: once the module has read the server's key
set and waits to be started, rotates the server's signing keys and only then starts it.

The suite's own plan runner starts that module the moment it is configured, leaving no moment to rotate in, so
run.ps1 keeps the module out of the plans it hands that runner and runs it here instead, once per such plan. Run
from the suite's scripts directory, with CONFORMANCE_SERVER naming the suite and HOST_ROTATE_URL the conformance
host's rotation endpoint.
Usage: python rotate-keys.py <configuration file> <plan specification>...
"""
import asyncio
import os
import sys

import httpx

import test_plan_parser
from conformance import Conformance

MODULE = "oidcc-server-rotate-keys"


async def run_once(suite, client, config, specification):
    plan = test_plan_parser.parse_test(specification)["test"]
    created = await suite.create_test_plan(plan["test_name"], config, plan.get("variants") or {})
    # A plan's variant can leave the module out, which the suite tells only once the plan exists
    if MODULE not in [module["testModule"] for module in created.get("modules", [])]:
        print(f"{specification}: no {MODULE} under this variant", flush=True)
        return True
    module = await suite.create_test_from_plan(created["id"], MODULE)
    module_id = module["id"]
    print(f"{specification}: created {MODULE} {module_id}", flush=True)

    state = await suite.wait_for_state(module_id, ["CONFIGURED", "FINISHED"])
    if state != "CONFIGURED":
        raise SystemExit(f"{MODULE} reached {state} before it could be started")

    response = await client.post(os.environ["HOST_ROTATE_URL"])
    if response.status_code != 204:
        raise SystemExit(f"The host refused to rotate its keys: HTTP {response.status_code}")

    await suite.start_test(module_id)
    await suite.wait_for_state(module_id, ["FINISHED"])
    result = (await suite.get_module_info(module_id)).get("result")
    print(f"{specification}: {MODULE} {result}", flush=True)
    return result == "PASSED"


async def main(config_file, specifications):
    suite = Conformance(os.environ["CONFORMANCE_SERVER"], None, False)
    await suite.wait_for_server_ready()
    with open(config_file, encoding="utf-8") as f:
        config = f.read()

    passed = True
    async with httpx.AsyncClient(verify=False) as client:
        for specification in specifications:
            passed = await run_once(suite, client, config, specification) and passed
    await suite.close_client()
    return 0 if passed else 1


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    sys.exit(asyncio.run(main(sys.argv[1], sys.argv[2:])))
