#!/bin/bash
#
# Copyright 2018 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

run_tests ()
{
	local TEST_ARGS=()
	if [ $USE_FVP == true ]
	then
		TEST_ARGS+=(--fvp)
	elif [ $USE_TFA == true ]
	then
		TEST_ARGS+=(--tfa)
	fi
	if [ $HAFNIUM_SKIP_LONG_RUNNING_TESTS == true ]
	then
		TEST_ARGS+=(--skip-long-running-tests)
	fi

	./kokoro/test.sh ${TEST_ARGS[@]}
}

source "$(dirname ${BASH_SOURCE[0]})/../build/bash/common.inc"

# Initialize global variables, prepare repo for building.
init_build

# Assign default values to variables.
if is_kokoro_build
then
	# Default config for Kokoro builds.
	default_value HAFNIUM_HERMETIC_BUILD true
	default_value HAFNIUM_SKIP_LONG_RUNNING_TESTS false
	default_value USE_TFA true
	default_value HAFNIUM_RUN_ASSERT_DISABLED_BUILD true
elif is_jenkins_build
then
	# Default config for Jenkins builds.
	default_value HAFNIUM_HERMETIC_BUILD false
	default_value HAFNIUM_SKIP_LONG_RUNNING_TESTS false
	default_value USE_TFA true
	default_value HAFNIUM_RUN_ASSERT_DISABLED_BUILD false
else
	# Default config for local builds.
	default_value HAFNIUM_HERMETIC_BUILD false
	default_value HAFNIUM_SKIP_LONG_RUNNING_TESTS true
	default_value USE_TFA false
	default_value HAFNIUM_RUN_ASSERT_DISABLED_BUILD false
fi

# If HAFNIUM_HERMETIC_BUILD is "true", relaunch this script inside a container.
# The 'run_in_container.sh' script will set the variable value to 'inside' to
# avoid recursion.
if [ "${HAFNIUM_HERMETIC_BUILD}" == "true" ]
then
	exec "${ROOT_DIR}/build/run_in_container.sh" "$(get_script_path)" $@
fi

USE_FVP=false

while test $# -gt 0
do
	case "$1" in
	--fvp)
		USE_FVP=true
		;;
	--skip-long-running-tests)
		HAFNIUM_SKIP_LONG_RUNNING_TESTS=true
		;;
	--run-assert-disabled-build)
		HAFNIUM_RUN_ASSERT_DISABLED_BUILD=true
		;;
	*)
		echo "Unexpected argument $1"
		exit 1
		;;
	esac
	shift
done

#
# Build and run tests with asserts disabled if required.
#
if [ "$HAFNIUM_RUN_ASSERT_DISABLED_BUILD" == "true" ]
then
	#
	# Call 'make clean' and remove args.gn file to ensure the value of
	# enable_assertions is updated from the default.
	#
	if [ -d "out/reference" ]; then
		make clean
		rm -f out/reference/build.ninja out/reference/args.gn
	fi

	make PROJECT=reference ENABLE_ASSERTIONS=0

	run_tests

	#
	# Call 'make clean' and remove args.gn file so future runs of make
	# include assertions.
	#
	make clean
	rm out/reference/build.ninja out/reference/args.gn
fi

#
# Build and run with asserts enabled.
#

make PROJECT=reference ENABLE_ASSERTIONS=1
run_tests
