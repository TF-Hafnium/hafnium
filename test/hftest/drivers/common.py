# Copyright 2025 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

import xml.etree.ElementTree as ET

import click
import collections
import datetime
import json
import os
import platform
import re
import time

MACHINE = platform.machine()

HFTEST_LOG_PREFIX = "[hftest] "
HFTEST_LOG_FAILURE_PREFIX = "Failure:"
HFTEST_LOG_FINISHED = "FINISHED"

HFTEST_CTRL_JSON_START = "[hftest_ctrl:json_start]"
HFTEST_CTRL_JSON_END = "[hftest_ctrl:json_end]"

HFTEST_CTRL_GET_COMMAND_LINE = "[hftest_ctrl:get_command_line]"
HFTEST_CTRL_FINISHED = "[hftest_ctrl:finished]"

HFTEST_CTRL_JSON_REGEX = re.compile("^\\[[0-9a-fA-F]+ [0-9a-fA-F]+\\] ")

HF_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

HF_PREBUILTS = os.path.join(HF_ROOT, "prebuilts")

VM_NODE_REGEX = "vm[1-9]"

def read_file(path):
    with open(path, "r", encoding="utf-8", errors="backslashreplace") as f:
        return f.read()

def write_file(path, to_write, append=False):
    with open(path, "a" if append else "w") as f:
        f.write(to_write)

def append_file(path, to_write):
    write_file(path, to_write, append=True)

def join_if_not_None(*args):
    return " ".join(filter(lambda x: x, args))

def get_vm_node_from_manifest(dts : str):
    """ Get VM node string from Partition's extension to Partition Manager's
    manifest."""
    match = re.search(VM_NODE_REGEX, dts)
    if not match:
        raise Exception("Partition's node is not defined in its manifest.")
    return match.group()

def correct_vm_node(dts: str, node_index : int):
    """ The vm node is being appended to the Partition Manager manifests.
    Ideally, these files would be reused accross various test set-ups."""
    return dts.replace(get_vm_node_from_manifest(dts), f"vm{node_index}")

def shared_options(f):
    f = click.option("--hypervisor")(f)
    f = click.option("--log", required=True)(f)
    f = click.option("--initrd")(f)
    f = click.option("--out_initrd")(f)
    f = click.option("--suite")(f)
    f = click.option("--test")(f)
    f = click.option("--vm_args")(f)
    f = click.option("--skip-long-running-tests", is_flag=True)(f)
    f = click.option("--force-long-running", is_flag=True)(f)
    f = click.option("--debug", is_flag=True, help="Makes platforms stall waiting for debugger connection.")(f)
    f = click.option("--show-output", is_flag=True)(f)
    f = click.option("--disable_visualisation", is_flag=True)(f)
    f = click.option("--log-level", help="Set the log level (DEBUG=10, INFO=20, WARNING=30, ERROR=40)")(f)
    return f

DT = collections.namedtuple("DT", ["dts", "dtb"])

class ArtifactsManager:
    """Class which manages folder with test artifacts."""

    def __init__(self, log_dir):
        self.created_files = []
        self.log_dir = log_dir

        # Create directory.
        try:
            os.makedirs(self.log_dir)
        except OSError:
            if not os.path.isdir(self.log_dir):
                raise
        print("Logs saved under", log_dir)

        # Create files expected by the Sponge test result parser.
        self.sponge_log_path = self.create_file("sponge_log", ".log")
        self.sponge_xml_path = self.create_file("sponge_log", ".xml")

    def gen_file_path(self, basename, extension):
        """Generate path to a file in the log directory."""
        return os.path.join(self.log_dir, basename + extension)

    def create_file(self, basename, extension):
        """Create and touch a new file in the log folder. Ensure that no other
        file of the same name was created by this instance of ArtifactsManager.
        """
        # Determine the path of the file.
        path = self.gen_file_path(basename, extension)

        # Check that the path is unique.
        assert(path not in self.created_files)
        self.created_files += [ path ]

        # Touch file.
        with open(path, "w") as f:
            pass

        return path

    def get_file(self, basename, extension):
        """Return path to a file in the log folder. Assert that it was created
        by this instance of ArtifactsManager."""
        path = self.gen_file_path(basename, extension)
        assert(path in self.created_files)
        return path


# Tuple used to return information about the results of running a set of tests.
TestRunnerResult = collections.namedtuple("TestRunnerResult", [
        "tests_run",
        "tests_failed",
        "tests_skipped",
    ])

class TestRunner:
    """Class which communicates with a test platform to obtain a list of
    available tests and driving their execution."""

    def __init__(self, artifacts, driver, test_set_up, suite_regex, test_regex,
            skip_long_running_tests, force_long_running, debug, show_output):
        self.artifacts = artifacts
        self.driver = driver
        self.test_set_up = test_set_up
        self.skip_long_running_tests = skip_long_running_tests
        self.force_long_running = force_long_running
        self.debug = debug
        self.show_output = show_output

        self.suite_re = re.compile(suite_regex or ".*")
        self.test_re = re.compile(test_regex or ".*")

    def extract_hftest_lines(self, raw):
        """Extract hftest-specific lines from a raw output from an invocation
        of the test platform."""
        lines = []
        lines_to_process = raw.splitlines()

        try:
            # If logs have logs of more than one VM, the loop below to extract
            # lines won't work. Thus, extracting between starting and ending
            # logs: HFTEST_CTRL_GET_COMMAND_LINE and HFTEST_CTRL_FINISHED.
            hftest_start = lines_to_process.index(HFTEST_CTRL_GET_COMMAND_LINE) + 1
            hftest_end = lines_to_process.index(HFTEST_CTRL_FINISHED)
        except ValueError:
            hftest_start = 0
            hftest_end = len(lines_to_process)

        lines_to_process = lines_to_process[hftest_start : hftest_end]

        for line in lines_to_process:
            match = HFTEST_CTRL_JSON_REGEX.search(line)
            if match is not None:
                line = line[match.end():]
            if line.startswith(HFTEST_LOG_PREFIX):
                lines.append(line[len(HFTEST_LOG_PREFIX):])
        return lines

    def get_test_json(self):
        """Invoke the test platform and request a JSON of available test and
        test suites."""
        out = self.driver.run("json", "json", self.force_long_running)
        hf_out = self.extract_hftest_lines(out)
        try:
            hf_out = hf_out[hf_out.index(HFTEST_CTRL_JSON_START) + 1
                        :hf_out.index(HFTEST_CTRL_JSON_END)];
        except ValueError as e:
            print("Unable to find JSON control string:")
            print(f"out={out}")
            print(f"hf_out={hf_out}")
            raise e

        hf_out = "\n".join(hf_out)
        try:
            return json.loads(hf_out)
        except ValueError as e:
            print("Unable to parse JSON:")
            print(f"out={out}")
            print(f"hf_out={hf_out}")
            print(out)
            raise e

    def collect_results(self, fn, it, xml_node):
        """Run `fn` on every entry in `it` and collect their TestRunnerResults.
        Insert "tests" and "failures" nodes to `xml_node`."""
        tests_run = 0
        tests_failed = 0
        tests_skipped = 0
        start_time = time.perf_counter()
        for i in it:
            sub_result = fn(i)
            assert(sub_result.tests_run >= sub_result.tests_failed)
            tests_run += sub_result.tests_run
            tests_failed += sub_result.tests_failed
            tests_skipped += sub_result.tests_skipped
        elapsed_time = time.perf_counter() - start_time

        xml_node.set("tests", str(tests_run + tests_skipped))
        xml_node.set("failures", str(tests_failed))
        xml_node.set("skipped", str(tests_skipped))
        xml_node.set("time", str(elapsed_time))
        return TestRunnerResult(tests_run, tests_failed, tests_skipped)

    def is_passed_test(self, test_out):
        """Parse the output of a test and return True if it passed."""
        return \
            len(test_out) > 0 and \
            test_out[-1] == HFTEST_LOG_FINISHED and \
            not any(l.startswith(HFTEST_LOG_FAILURE_PREFIX) for l in test_out)

    def get_failure_message(self, test_out):
        """Parse the output of a test and return the message of the first
        assertion failure."""
        for i, line in enumerate(test_out):
            if line.startswith(HFTEST_LOG_FAILURE_PREFIX) and i + 1 < len(test_out):
                # The assertion message is on the line after the 'Failure:'
                return test_out[i + 1].strip()

        return None

    def get_log_name(self, suite, test):
        """Returns a string with a generated log name for the test."""
        log_name = ""

        cpu = self.driver.args.cpu
        if cpu:
            log_name += cpu + "."

        log_name += suite["name"] + "." + test["name"]

        return log_name

    def run_test(self, suite, test, suite_xml):
        """Invoke the test platform and request to run a given `test` in given
        `suite`. Create a new XML node with results under `suite_xml`.
        Test only invoked if it matches the regex given to constructor."""
        if not self.test_re.match(test["name"]):
            return TestRunnerResult(tests_run=0, tests_failed=0, tests_skipped=0)

        test_xml = ET.SubElement(suite_xml, "testcase")
        test_xml.set("name", test["name"])
        test_xml.set("classname", suite["name"])

        if (self.skip_long_running_tests and test["is_long_running"]) or test["skip_test"]:
            print("      SKIP", test["name"])
            test_xml.set("status", "notrun")
            skipped_xml = ET.SubElement(test_xml, "skipped")
            skipped_xml.set("message", "Long running")
            return TestRunnerResult(tests_run=0, tests_failed=0, tests_skipped=1)

        action_log = "DEBUG" if self.debug else "RUN"
        print(f"      {action_log}", test["name"])
        log_name = self.get_log_name(suite, test)

        test_xml.set("status", "run")

        start_time = time.perf_counter()
        out = self.driver.run(
            log_name, "run {} {}".format(suite["name"], test["name"]),
            test["is_long_running"] or self.force_long_running,
            self.debug, self.show_output)

        hftest_out = self.extract_hftest_lines(out)
        elapsed_time = time.perf_counter() - start_time

        test_xml.set("time", str(elapsed_time))

        system_out_xml = ET.SubElement(test_xml, "system-out")
        system_out_xml.text = out

        if self.is_passed_test(hftest_out):
            print("        PASS")
            return TestRunnerResult(tests_run=1, tests_failed=0, tests_skipped=0)
        else:
            print("[x]     FAIL --", self.driver.get_run_log(log_name))
            failure_xml = ET.SubElement(test_xml, "failure")
            failure_message = self.get_failure_message(hftest_out) or "Test failed"
            failure_xml.set("message", failure_message)
            failure_xml.text = '\n'.join(hftest_out)
            return TestRunnerResult(tests_run=1, tests_failed=1, tests_skipped=0)

    def run_suite(self, suite, xml):
        """Invoke the test platform and request to run all matching tests in
        `suite`. Create new XML nodes with results under `xml`.
        Suite skipped if it does not match the regex given to constructor."""
        if not self.suite_re.match(suite["name"]):
            return TestRunnerResult(tests_run=0, tests_failed=0, tests_skipped=0)

        print("    SUITE", suite["name"])
        suite_xml = ET.SubElement(xml, "testsuite")
        suite_xml.set("name", suite["name"])
        properties_xml = ET.SubElement(suite_xml, "properties")

        property_xml = ET.SubElement(properties_xml, "property")
        property_xml.set("name", "driver")
        property_xml.set("value", type(self.driver).__name__)

        if self.driver.args.cpu:
            property_xml = ET.SubElement(properties_xml, "property")
            property_xml.set("name", "cpu")
            property_xml.set("value", self.driver.args.cpu)

        return self.collect_results(
            lambda test: self.run_test(suite, test, suite_xml),
            suite["tests"],
            suite_xml)

    def run_tests(self):
        """Run all suites and tests matching regexes given to constructor.
        Write results to sponge log XML. Return the number of run and failed
        tests."""

        test_spec = self.get_test_json()
        timestamp = datetime.datetime.now().replace(microsecond=0).isoformat()

        xml = ET.Element("testsuites")
        xml.set("name", self.test_set_up)
        xml.set("timestamp", timestamp)

        result = self.collect_results(
            lambda suite: self.run_suite(suite, xml),
            test_spec["suites"],
            xml)

        # Write XML to file.
        ET.ElementTree(xml).write(self.artifacts.sponge_xml_path,
            encoding='utf-8', xml_declaration=True)

        if result.tests_failed > 0:
            print("[x] FAIL:", result.tests_failed, "of", result.tests_run,
                    "tests failed")
        elif result.tests_run > 0:
            print("    PASS: all", result.tests_run, "tests passed")

        # Let the driver clean up.
        self.driver.finish()

        return result
