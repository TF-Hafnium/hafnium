Commits Style
=============

When writing commit messages, please think carefully about the purpose and scope
of the change you are making: describe briefly what the change does, and
describe in details why it does it. This helps to ensure that changes to the
code-base are transparent and approachable to reviewers, and it allows maintainers
to keep a more accurate changelog. You may use Markdown in commit messages.

A good commit message provides all the background information needed for
reviewers to understand the intent and rationale of the patch. This information
is also useful for future reference.

For example:

- What does the patch do?
- What motivated it?
- What impact does it have?
- How was it tested?
- Have alternatives been considered? Why did you choose this approach over
  another one?
- If it fixes an issue, detail what the issue is and provide any pointers/resources
  that are found necessary.

Hafnium follows the `Conventional Commits`_ specification. All commits to the
main repository and its submodules are expected to adhere to these guidelines,
so it is **strongly** recommended that you read at least the `quick summary`_
of the specification.

To briefly summarize, commit messages are expected to be of the form:

.. code::

    <type>[optional scope]: <description>

    [optional body]

    [optional footer(s)]

    Signed-off-by: Contributor <contributor@email.com>
    Change-Id: 00000000000000000000000000000000000000000

The maximum character counts per line are:

* 50 for the commit title.
* 72 for the commit body.

The following `types` are permissible and are strictly enforced:

+--------------+---------------------------------------------------------------+
| Type         | Description                                                   |
+==============+===============================================================+
| ``feat``     | A new feature                                                 |
+--------------+---------------------------------------------------------------+
| ``fix``      | A bug fix                                                     |
+--------------+---------------------------------------------------------------+
| ``build``    | Changes that affect the build system or external dependencies |
+--------------+---------------------------------------------------------------+
| ``ci``       | Changes to CI configuration files and scripts                 |
+--------------+---------------------------------------------------------------+
| ``docs``     | Documentation-only changes                                    |
+--------------+---------------------------------------------------------------+
| ``perf``     | A code change that improves performance                       |
+--------------+---------------------------------------------------------------+
| ``refactor`` | A code change that neither fixes a bug nor adds a feature     |
+--------------+---------------------------------------------------------------+
| ``revert``   | Changes that revert a previous change                         |
+--------------+---------------------------------------------------------------+
| ``style``    | Changes that do not affect the meaning of the code            |
|              | (white-space, formatting, missing semi-colons, etc.)          |
+--------------+---------------------------------------------------------------+
| ``test``     | Adding missing tests or correcting existing tests             |
+--------------+---------------------------------------------------------------+
| ``chore``    | Any other change                                              |
+--------------+---------------------------------------------------------------+

While we don't enforce scopes strictly, we do ask that commits use these if they
can. These should reference the functionality the patch relates to.

Mandated Trailers
-----------------

Commits are expected to be signed off with the ``Signed-off-by:`` trailer using
your real name and email address. You can do this automatically by committing
with Git's ``-s`` flag.

There may be multiple ``Signed-off-by:`` lines depending on the history of the
patch, but one **must** be the committer. More details may be found in the
`Gerrit Signed-off-by Lines guidelines`_.

Ensure that each commit also has a unique ``Change-Id:`` line.

If you have followed optional steps in the prerequisites to install the clone the
repository using the "`Clone with commit-msg hook`" clone method, then this should
be done automatically for you.

More details may be found in the `Gerrit Change-Ids documentation`_.

.. _Conventional Commits: https://www.conventionalcommits.org/en/v1.0.0
.. _Gerrit Change-Ids documentation: https://review.trustedfirmware.org/Documentation/user-changeid.html
.. _Gerrit Signed-off-by Lines guidelines: https://review.trustedfirmware.org/Documentation/user-signedoffby.html
.. _quick summary: https://www.conventionalcommits.org/en/v1.0.0/#summary

--------------

*Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.*
