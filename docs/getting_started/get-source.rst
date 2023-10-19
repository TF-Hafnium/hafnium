Getting the source code
=======================

Hafnium source code is maintained in a Git repository hosted on trustedfirmware.org.
To clone this repository from the server, run the following in your shell:

.. code:: shell

    git clone --recurse-submodules https://git.trustedfirmware.org/hafnium/hafnium.git

In order to import gerrit hooks useful to add a Change-Id footer in commit messages,
it is recommended to use:

.. code:: shell

   git clone --recurse-submodules https://git.trustedfirmware.org/hafnium/hafnium.git && { cd hafnium && f="$(git rev-parse --git-dir)"; curl -Lo "$f/hooks/commit-msg" https://review.trustedfirmware.org/tools/hooks/commit-msg && { chmod +x "$f/hooks/commit-msg"; git submodule --quiet foreach "cp \"\$toplevel/$f/hooks/commit-msg\" \"\$toplevel/$f/modules/\$path/hooks/commit-msg\""; }; }

--------------

*Copyright (c) 2023, Arm Limited. All rights reserved.*
