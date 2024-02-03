# Copyright 2019 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

CONTAINER_TAG="hafnium_dev"

if [[ ! -v DOCKER ]]
then
	DOCKER="$(which docker)" \
		|| (echo "ERROR: Could not find Docker binary" 1>&2; exit 1)
fi
