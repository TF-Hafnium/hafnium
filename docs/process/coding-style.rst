Coding Style
============

Hafnium's coding style has been based on the `Linux coding style`_ with explicit
modifications: always use braces for conditionals and loops.

The project follows the subset of the `Google C++ style guide`_ that is applicable
to C.

Much of this is automated by the use of clang-format and clang-tidy, but that
doesn't capture everything.
Where the style enforced by this tooling conflicts with what is in this document,
we accept what the tooling requires, and try to improve it if possible.

Clarifications
--------------

* Yes, it does mean all variables are declared, C90-style, at the top of
  scope, even those loop induction variables.
* Linux encourages no braces around single-statement branches. We follow
  Google style guide and require braces around all scope blocks.

Naming symbols
--------------

* Arch-specific functions should start with `arch_`.
* Platform-specific functions should start with `plat_`.
* Non-static functions should generally start with the name of the file they
  are declared in (after the `arch_` or `plat_` prefix if appropriate), though
  there are quite a few exceptions to this rule.
* Prefer `x_count` over `num_x`.

Prose
-----

These rules apply to comments and other natural language text.

* Capitalize acronyms.
   * CPU, vCPU, VM, SP, EL2, FF-A, FVP.
* Spell out Hafnium in full, not Hf.
* Use single spaces.
* Sentences end with full stops.
* If the comment fits on one line use `/* */`, otherwise space it out:

.. code:: C

  /*
   * Informative long comment
   * with extra information.
   */

* Doc-ish comments start with `/**`.
   * Use for:
      *   Function definitions (not declarations)
      *   Struct declarations
      *   Enum values
   * Do not use for:
      *   Macros
      *   Definitions of globals

* References to code symbols use backticks, e.g. \`my_symbol\`.

Coding practices
----------------

*   Function macros should be functions instead, that way you get types.
*   Lock ordering is described at the top of `api.c`_.
*   Use opaque types to avoid implicit casts when it will help avoid mistakes.
    e.g. `addr.h`_.
*   Avoid inline casting. C doesn't give much protection so be formal about the
    transformations. e.g. `addr.h`_.
*   If a function acquires a resource, there must be a single exit path to free
    the resource. Tracking down multiple exit points is hard and requires
    duplicated code which is harder. This may require splitting functions into
    subfunctions. Early exit is okay if there aren't any clean up tasks.
*   Don't use function pointers. It makes analysis hard and is often a target of
    attacks.
*   Be liberal with `CHECK`. Use it to assert pre-/post- conditions.
*   No self-modifying code.
*   Build targets should include all the direct dependencies for their sources,
    where possible, rather than relying on transitive dependencies.

Logging
-------

Hafnium uses the same log levels as |TF-A|. There are 5 log levels, in order
of severity:

1.  `ERROR`:
    Use this only for cases where there is an error in the partition manager
    itself, perhaps caused by a coding error, bad configuration, unexpected
    hardware behaviour or a malformed manifest. Errors should not be logged
    during normal operation, even in case of a buggy or malicious VM.

2.  `NOTICE`:
    Use this sparingly for important messages which should be logged even in
    production builds because they will be useful for debugging. This is a
    suitable level to use for events which may indicate a bug in a VM.

3.  `WARNING`:
    Use this for warnings which are important to developers but can generally be
    ignored in production.

4.  `INFO`:
    Use this to provide extra information that is helpful for developers.

5.  `VERBOSE`:
    Use this to provide even more information which may be helpful when tracing
    through execution in detail, such as when debugging test failures. This is
    the only level which should include any sensitive data.

Logging is done with the `dlog_*` macros, e.g. `dlog_info`. These accept
printf-style format strings and arguments.

The log level of a build is controlled by the `log_level` argument defined in
`build/BUILD.gn`_. This defaults to `INFO` for debug builds and tests, meaning
that all levels except `VERBOSE` will be logged. It is recommended to set the
log level to `NOTICE` for production builds, to reduce binary size and log spam.
Verbosity can also be changed for a given platform build only, in the respective
platform configuration.

--------------

*copyright (c) 2023, arm limited and contributors. all rights reserved.*

.. _Linux coding style: https://www.kernel.org/doc/html/v4.17/process/coding-style.html
.. _Google C++ style guide: https://google.github.io/styleguide/cppguide.html
.. _api.c: https://git.trustedfirmware.org/hafnium/hafnium.git/tree/src/api.c
.. _addr.h: https://git.trustedfirmware.org/hafnium/hafnium.git/tree/inc/hf/addr.h
.. _build/BUILD.gn: https://git.trustedfirmware.org/hafnium/hafnium.git/tree/build/BUILD.gn#n65
