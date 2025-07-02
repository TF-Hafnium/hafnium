# Copyright 2025 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

import importlib

from common import (
    HFTEST_CTRL_FINISHED,
    HFTEST_CTRL_GET_COMMAND_LINE
)
from driver import Driver

class SerialDriver(Driver):
    """Driver which communicates with a device over the serial port."""

    def __init__(self, args, tty_file, baudrate, init_wait):
        Driver.__init__(self, args)
        self.tty_file = tty_file
        self.baudrate = baudrate
        self.pyserial = importlib.import_module("serial")

        if init_wait:
            input("Press ENTER and then reset the device...")

    def connect(self):
        return self.pyserial.Serial(self.tty_file, self.baudrate, timeout=10)

    def run(self, run_name, test_args, is_long_running):
        """Communicate `test_args` to the device over the serial port."""
        run_state = self.start_run(run_name)

        with self.connect() as ser:
            with open(run_state.log_path, "a") as f:
                while True:
                    # Read one line from the serial port.
                    line = ser.readline().decode('utf-8')
                    if len(line) == 0:
                        # Timeout
                        run_state.set_ret_code(124)
                        input("Timeout. " +
                            "Press ENTER and then reset the device...")
                        break
                    # Write the line to the log file.
                    f.write(line)
                    if HFTEST_CTRL_GET_COMMAND_LINE in line:
                        # Device is waiting for `test_args`.
                        ser.write(test_args.encode('ascii'))
                        ser.write(b'\r')
                    elif HFTEST_CTRL_FINISHED in line:
                        # Device has finished running this test and will reboot.
                        break

        return self.finish_run(run_state)

    def finish(self):
        """Clean up after running tests."""
        with self.connect() as ser:
            while True:
                line = ser.readline().decode('utf-8')
                if len(line) == 0:
                    input("Timeout. Press ENTER and then reset the device...")
                elif HFTEST_CTRL_GET_COMMAND_LINE in line:
                    # Device is waiting for a command. Instruct it to exit
                    # the test environment.
                    ser.write("exit".encode('ascii'))
                    ser.write(b'\r')
                    break
