#!/bin/bash
#
# Copyright 2023 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

################################################################################
# CI VARIABLES:
# workspace, warehouse, artefacts
# GLOBAL VARIABLES:
# OUTDIR, PROJECT, FALLBACK_PLUGIN_URL, FALLBACK_FILES, PLUGIN_BINARY
################################################################################
set +u
QA_REPO=${QA_REPO_PUBLIC:-https://git.gitlab.arm.com/tooling/qa-tools.git}
QA_REPO_NAME=qa-tools
QA_REFSPEC=${QA_REFSPEC:-master}
# Internal globals
DEBUG_FOLDER=${artefacts}/debug
RELEASE_FOLDER=${artefacts}/release
TRACE_FILE_PREFIX=covtrace
PROJECT="HAFNIUM"
BIN_SECTION=""
# INDEXED BY ELF FILE
declare -g -A TRACE_FILES=()
declare -g COUNTER=0


################################################################################
# Enable the code coverage tool
#
# This function enables the plugin to produce trace logs on the FVP
# and set variables for the post-processing stage.
#
# GLOBALS:
#   WORKSPACE, CODE_COVERAGE_FOLDER, INFO_FILE, REPORT_FOLDER, CONFIG_JSON,
#   INTERMEDIATE_LAYER_FILE, OBJDUMP, READELF, FALLBACK_FILES
# ARGUMENTS:
#   None
# OUTPUTS:
#   lcov binaries
# RETURN:
#   0 if succeeds, non-zero on error.
################################################################################
enable_code_coverage() {
  # Load code coverage binary
  echo "Code coverage for binaries enabled..."
  export OUTDIR=${WORKSPACE}/out/reference
  mkdir -p $OUTDIR
  CODE_COVERAGE_FOLDER="${OUTDIR}/qa-code-coverage"
  INFO_FILE=${CODE_COVERAGE_FOLDER}/coverage.info
  REPORT_FOLDER=${CODE_COVERAGE_FOLDER}/lcov
  CONFIG_JSON=${CODE_COVERAGE_FOLDER}/configuration_file.json
  INTERMEDIATE_LAYER_FILE=${CODE_COVERAGE_FOLDER}/intermediate_layer.json
  OBJDUMP="$(which 'aarch64-none-elf-objdump')"
  READELF="$(which 'aarch64-none-elf-readelf')"
  FALLBACK_FILES="coverage_trace.so,coverage_trace.o,plugin_utils.o"
  build_tool
  lcov --version || install_lcov
}


################################################################################
# Install lcov from source
#
# GLOBALS:
#   None
# ARGUMENTS:
#   $1 Folder where lcov will be installed
#   $2 Lcov version to be installed
# OUTPUTS:
#   lcov binaries
# RETURN:
#   0 if succeeds, non-zero on error.
################################################################################
install_lcov() {
  local lcov_folder=${1:-$HOME/lcov}
  local lcov_version=${2:-v1.16}

  echo "Cloning lcov ${lcov_version} at folder $(pwd)..."
  git clone https://github.com/linux-test-project/lcov.git
  cd lcov
  git checkout $lcov_version
  echo "Installing lcov at folder ${lcov_folder}..."
  make PREFIX=${lcov_folder} install
  cd ..
  # Make it available
  export PATH=$PATH:${lcov_folder}/bin
  lcov --version
  genhtml --version
}


################################################################################
# Deploy qa-tools into the current directory
# GLOBALS:
#   QA_REPO, QA_REPO_NAME, QA_REFSPEC
# ARGUMENTS:
#   None
# OUTPUTS:
#   Clones the qa-tools repo from the global variables with the given
#   commit hash.
# RETURN:
#   0 if succeeds, non-zero on error.
################################################################################
deploy_qa_tools() {
  git clone "${QA_REPO}" ${QA_REPO_NAME}
  cd ${QA_REPO_NAME} && git checkout "${QA_REFSPEC}" && cd ..
}


################################################################################
# Builds or downloads the QA Code Coverage Tool
# GLOBALS:
#   CODE_COVERAGE_FOLDER, QA_REPO, QA_REPO_NAME, QA_REFSPEC, FALLBACK_PLUGIN_URL
# ARGUMENTS:
#   None
# OUTPUTS:
#   Creates coverage folder and builds/downloads there the plugin binaries.
#   It exports the binary plugin location to coverage_trace_plugin.
# RETURN:
#   0 if succeeds, non-zero on error.
################################################################################
build_tool() {
  echo "Building QA Code coverage tool..."
  PLUGIN_BINARY="${FALLBACK_FILES%%,*}" # The first in the list of the binary files
  local PVLIB_HOME="warehouse/SysGen/PVModelLib/$model_version/$model_build/external"
  local LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CODE_COVERAGE_FOLDER
  mkdir -p ${CODE_COVERAGE_FOLDER}
  pushd "${CODE_COVERAGE_FOLDER}"
  deploy_qa_tools
  local cc_source=$(find . -type f -name 'coverage_trace.cc')
  for ff in ${FALLBACK_FILES//,/ }
  do
    wget -q "${FALLBACK_PLUGIN_URL}/${ff}"
  done
  export coverage_trace_plugin="${CODE_COVERAGE_FOLDER}/${PLUGIN_BINARY}"
  popd
}

################################################################################
# Returns the sources (SCM) indicated in the configuration file.
#
# Returns a multiline string in JSON format that contains the sources used to
# build the binaries for the defined project.
#
# ENVIRONMENT VARIABLES:
#   GERRIT_PROJECT, GERRIT_REFSPEC
# ARGUMENTS:
# OUTPUTS:
#   Source SCM parameters in a JSON format as string.
# RETURN:
#   0 if succeeds, non-zero on error.
################################################################################
get_scm_sources() {
  local scm_sources=""

  read -r -d '' scm_sources << EOM
          [
              {
              "type": "git",
              "URL":  "https://review.trustedfirmware.org/hafnium/hafnium",
              "COMMIT": "",
              "REFSPEC": "${HF_REFSPEC}",
              "LOCATION": "hafnium"
              }
          ]
EOM
  echo "$scm_sources"
}

################################################################################
# Creates the input configuration file to create the intermediate layer.
#
# GLOBALS:
#   TRACE_FILES, CONFIG_JSON, OBJDUMP, READELF, INTERMEDIATE_LAYER_FILE
# ARGUMENTS:
#   $1: Workspace where the sources were located when the binaries were built.
#   $2: Optional metadata.
# OUTPUTS:
#   Input configuration file for the intermediate layer.
################################################################################
create_configuration_file() {

  # Obtaining binaries from array
  bin_section=""
  comma=""
  for elf_file in "${!TRACE_FILES[@]}"
  do
      local trace_files="${TRACE_FILES[$elf_file]}"
      bin_section=$(cat <<-END
      ${bin_section}${comma}
                    {
                        "name": "$elf_file",
                        "traces": [
                                    ${trace_files%,*}
                                  ]
                    }
END

)
  comma=","
  parent="$(basename "$(dirname "$elf_file")")"
  mkdir -p ${CODE_COVERAGE_FOLDER}/${parent}
  cp $elf_file ${CODE_COVERAGE_FOLDER}/${parent}/.
  done

cat <<EOF > "${CONFIG_JSON}"
{
  "configuration":
      {
      "remove_workspace": true,
      "include_assembly": true
      },
  "parameters":
      {
      "objdump": "${OBJDUMP}",
      "readelf": "${READELF}",
      "sources": $(get_scm_sources),
      "workspace": "${1:-$WORKSPACE}",
      "output_file": "${INTERMEDIATE_LAYER_FILE}",
      "include_only": "${INCLUDE_FILES}",
      "exclude": "${EXCLUDE_FILES}",
      "metadata": "${2}"
      },
  "elfs": [
          ${bin_section}
      ]
}
EOF
}

################################################################################
# Appends a trace file glob to a given elf/axf file.
#
# GLOBALS:
#   TRACE_FILES
# ARGUMENTS:
#   $1: Full path to binary (elf/axf) file.
#   $2: Full path trace glob belonging to traces linked to the binary file.
# OUTPUTS:
#   Appended trace glob to the TRACE_FILES global array
################################################################################
append_elf_file() {
  local elf_file="$1"
  local trace_glob="$2"
  TRACE_FILES[$elf_file]+="\"$trace_glob\",
  "
}

################################################################################
# Moves trace files from one location to another.
#
# Copies the trace files from one location to another hardcoded folder setup
# where later can be processed for the intermediate layer.
#
# GLOBALS:
#   COUNTER, CODE_COVERAGE_FOLDER, TRACE_FILE_PREFIX
# ARGUMENTS:
#   $1: Full path where the trace files reside.
#   $2: Variable by reference that contains the new path for the trace files.
# OUTPUTS:
#   Path where the trace files were copied.
################################################################################
move_log_files() {
  local origin_folder="$1"
  declare -n local_trace_folder=$2
  COUNTER=$(( COUNTER + 1))
  local destination_trace_folder=${CODE_COVERAGE_FOLDER}/traces-${COUNTER}
  mkdir -p ${destination_trace_folder}
  find ${origin_folder} -maxdepth 1 -name ${TRACE_FILE_PREFIX}'-*.log' -type f -size +0 -exec cp {} ${destination_trace_folder} \;
  # Pass the destination trace folder to calling script
  local_trace_folder="${destination_trace_folder}/${TRACE_FILE_PREFIX:-covtrace}"'-*.log'
}

################################################################################
# Generates intermediate layer (json) from configuration file
# GLOBALS:
#   CODE_COVERAGE_FOLDER, QA_REPO_NAME, CONFIG_JSON
# ARGUMENTS:
#   None
# OUTPUTS:
#   Intermediate layer (json) file at the folder indicated in the configuration
#   file.
################################################################################
generate_intermediate_layer() {
  python3 ${CODE_COVERAGE_FOLDER}/${QA_REPO_NAME}/coverage-tool/coverage-reporting/intermediate_layer.py \
    --config-json ${CONFIG_JSON}
}

################################################################################
# Creates LCOV coverage report.
# GLOBALS:
#   CODE_COVERAGE_FOLDER, workspace, INTERMEDIATE_LAYER_FILE, INFO_FILE,
#   REPORT_FOLDER
# ARGUMENTS:
#   None
# OUTPUTS:
#   A coverage info file.
#   LCOV HTML coverage report.
# RETURN:
#   0 if succeeds, non-zero on error.
################################################################################
create_coverage_report() {
	python3 ${CODE_COVERAGE_FOLDER}/${QA_REPO_NAME}/coverage-tool/coverage-reporting/generate_info_file.py \
	--workspace ${WORKSPACE} --json ${INTERMEDIATE_LAYER_FILE} --info ${INFO_FILE}
	genhtml --branch-coverage ${INFO_FILE} --output-directory ${REPORT_FOLDER}
}


################################################################################
# Creates an HTML table with the summary of the code coverage.
#
# Extracts the summary indicators from the main html code coverage report and
# creates an HTML report to be shown on the building page.
#
# GLOBALS:
#   REPORT_FOLDER, WORKSPACE, BUILD_URL
# ARGUMENTS:
#   $1: Full path where HTML report will be created.
#   $2: Location of the main html file for the code coverage.
# OUTPUTS:
#   HTML report code coverage summary.
# RETURN:
#   0 if succeeds, non-zero on error.
################################################################################
generate_header() {
    local out_report=$1
    local cov_html=${2:-$REPORT_FOLDER/index.html}
python3 - << EOF
import re
import json
import os

cov_html="$cov_html"
out_report = "$out_report"
origin_html = os.path.relpath(cov_html, "$WORKSPACE")

with open(cov_html, "r") as f:
    html_content = f.read()
items = ["Lines", "Functions", "Branches"]
s = """
<style>
/* Result colors */
.success {
background-color: #b4fd98;
}
.failure {
background-color: #ffb8b8;
}
.unstable {
background-color: #ffe133;
}
</style>
    <div id="div-cov">
    <hr>
        <table id="table-cov">
              <tbody>
                <tr>
                    <td>Type</td>
                    <td>Hit</td>
                    <td>Total</td>
                    <td>Coverage</td>
              </tr>
"""
for item in items:
    data = re.findall(r'<td class="headerItem">{}:</td>\n\s+<td class="headerCovTableEntry">(.+?)</td>\n\s+<td class="headerCovTableEntry">(.+?)</td>\n\s+'.format(item),
    html_content, re.DOTALL)
    if data is None:
        continue
    hit, total = data[0]
    cov = round(float(hit)/float(total) * 100.0, 2)
    color = "success"
    if cov < 90:
        color = "unstable"
    if cov < 75:
        color = "failure"
    s = s + """
                <tr>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td class='{}'>{} %</td>
                </tr>
""".format(item, hit, total, color, cov)
s = s + """
            </tbody>
        </table>
        <p>
        <button onclick="window.open('{}artifact/{}','_blank');">Total Coverage Report</button>
        </p>
    </div>

""".format("$BUILD_URL", origin_html)
with open(out_report, "a") as f:
    f.write(s)
EOF
}
