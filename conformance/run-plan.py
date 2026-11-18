"""Runs the suite's own plan runner, reading a module's details only once the suite has recorded how it ended.

The runner waits for a module through the suite's wait-state endpoint and then reads the module's details from the info
endpoint, which answers with the stored record. The suite sets a module's status in memory a moment before it writes the
record, and the wait-state endpoint can answer from memory in that moment, so the record still carries the previous
status: a module that ended is read as still waiting, and the runner fails the whole run as one that did not run to
completion, before it judges any expected failure or warning. Here the details are read again while the module has not
ended, for about ten seconds at most, so a module that really is stuck is still reported as incomplete. Run from the
suite's scripts directory, with the runner's arguments.
Usage: python run-plan.py <runner arguments>...
"""
import asyncio
import os
import runpy
import sys

# Run as a file from another directory, this script would not find the suite's modules beside the runner
sys.path.insert(0, os.getcwd())

from conformance import Conformance  # noqa: E402

ENDED = ("FINISHED", "INTERRUPTED")
READS = 20
PAUSE_SECONDS = 0.5

read_module_info = Conformance.get_module_info


async def read_ended_module_info(suite, module_id):
    info = await read_module_info(suite, module_id)
    for _ in range(READS):
        if info.get("status") in ENDED:
            break
        await asyncio.sleep(PAUSE_SECONDS)
        info = await read_module_info(suite, module_id)
    return info


Conformance.get_module_info = read_ended_module_info

RUNNER = "run-test-plan.py"
sys.argv[0] = RUNNER
runpy.run_path(RUNNER, run_name="__main__")
