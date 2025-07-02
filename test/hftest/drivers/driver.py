# Copyright 2025 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

import collections
import subprocess

from common import (
    append_file,
    read_file,
    HFTEST_LOG_FAILURE_PREFIX,
    HFTEST_LOG_PREFIX,
)

# Tuple holding the arguments common to all driver constructors.
# This is to avoid having to pass arguments from subclasses to superclasses.
DriverArgs = collections.namedtuple("DriverArgs", [
        "artifacts",
        "hypervisor",
        "spmc",
        "initrd",
        "vm_args",
        "cpu",
        "partitions",
        "global_run_name",
        "coverage_plugin",
        "disable_visualisation"
    ])

# State shared between the common Driver class and its subclasses during
# a single invocation of the target platform.
class DriverRunState:
    def __init__(self, log_path):
        self.log_path = log_path
        self.ret_code = 0

    def set_ret_code(self, ret_code):
        self.ret_code = ret_code

class DriverRunException(Exception):
    """Exception thrown if subprocess invoked by a driver returned non-zero
    status code. Used to fast-exit from a driver command sequence."""
    pass


class Driver:
    """Parent class of drivers for all testable platforms."""

    def __init__(self, args):
        self.args = args

    def get_run_log(self, run_name):
        """Return path to the main log of a given test run."""
        return self.args.artifacts.get_file(run_name, ".log")

    def start_run(self, run_name):
        """Hook called by Driver subclasses before they invoke the target
        platform."""
        return DriverRunState(self.args.artifacts.create_file(run_name, ".log"))

    def exec_logged(self, run_state, exec_args, cwd=None, env=None):
        """Run a subprocess on behalf of a Driver subclass and append its
        stdout and stderr to the main log."""
        assert(run_state.ret_code == 0)
        with open(run_state.log_path, "a") as f:
            f.write("$ {}\r\n".format(" ".join(exec_args)))
            f.flush()
            ret_code = subprocess.call(exec_args, stdout=f, stderr=f, cwd=cwd, env=env)
            if ret_code != 0:
                run_state.set_ret_code(ret_code)
                raise DriverRunException()

    def finish_run(self, run_state):
        """Hook called by Driver subclasses after they finished running the
        target platform. `ret_code` argument is the return code of the main
        command run by the driver. A corresponding log message is printed."""
        # Decode return code and add a message to the log.
        with open(run_state.log_path, "a") as f:
            if run_state.ret_code == 124:
                f.write("\r\n{}{} timed out\r\n".format(
                    HFTEST_LOG_PREFIX, HFTEST_LOG_FAILURE_PREFIX))
            elif run_state.ret_code != 0:
                f.write("\r\n{}{} process return code {}\r\n".format(
                    HFTEST_LOG_PREFIX, HFTEST_LOG_FAILURE_PREFIX,
                    run_state.ret_code))

        # Append log of this run to full test log.
        log_content = read_file(run_state.log_path)
        append_file(
            self.args.artifacts.sponge_log_path,
            log_content + "\r\n\r\n")
        return log_content
