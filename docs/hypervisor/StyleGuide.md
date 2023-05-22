# Style guide

Hafnium's coding style has been based on the
[Linux style](https://www.kernel.org/doc/html/v4.17/process/coding-style.html)
with explicit modifications:

*   Always use braces for conditionals and loops. (No SSL `goto fail;`, thanks.)

Following this, we generally fall back to the subset of the
[Google C++ style guide](https://google.github.io/styleguide/cppguide.html) that
is applicable to C.

We try to automate this where possible with clang-format and clang-tidy but that
doesn't capture everything we'd like today. Where the style enforced by this
tooling conflicts with what is in this document we accept what the tooling
requires, and try to improve it if possible.

## Clarifications

*   Yes, it does mean all variables are declared, C90-style, at the top of
    scope, even those loop induction variables.
*   Linux encourages no braces around single-statement branches. We follow
    Google and require braces around all scope blocks.

## Naming symbols

*   Arch-specific functions should start with `arch_`.
*   Platform-specific functions should start with `plat_`.
*   Non-static functions should generally start with the name of the file they
    are declared in (after the `arch_` or `plat_` prefix if appropriate), though
    there are quite a few exceptions to this rule.
*   Prefer `x_count` over `num_x`.

## Prose

These rules apply to comments and other natural language text.

*   Capitalize acronyms.
    *   CPU, vCPU, VM, EL2, FF-A, QEMU
*   Spell out Hafnium in full, not Hf.
*   Use single spaces.
*   Sentences end with full stops.
*   If the comment fits on one line use `/* */`, otherwise space it out:

    ```
    /*
     * Informative long comment
     * with extra information.
     */
    ```

*   Doc-ish comments start with `/**`.

    *   Use for:
        *   Function definitions (not declarations)
        *   Struct declarations
        *   Enum values
    *   Do not use for:
        *   Macros
        *   Definitions of globals

*   References to code symbols use backticks, e.g. `` `my_symbol` ``.

## Coding practices

*   Function macros should be functions instead, that way you get types.
*   Lock ordering is described at the top of [`api.c`](../../src/api.c).
*   Use opaque types to avoid implicit casts when it will help avoid mistakes.
    e.g. [`addr.h`](../../inc/hf/addr.h)
*   Avoid inline casting. C doesn't give much protection so be formal about the
    transformations. e.g. [`addr.h`](../../inc/hf/addr.h)
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

## Logging

Hafnium uses the same log levels as Arm Trusted Firmware. There are 5 log
levels, in order of severity:

1.  `ERROR`

    Use this only for cases that there is an error in the hypervisor itself,
    perhaps caused by a coding error, bad configuration, unexpected hardware
    behaviour or a malformed manifest. Errors should not be logged during normal
    operation, even in case of a buggy or malicious VM.

2.  `NOTICE`

    Use this sparingly for important messages which should be logged even in
    production builds because they will be useful for debugging. This is a
    suitable level to use for events which may indicate a bug in a VM.

3.  `WARNING`

    Use this for warnings which are important to developers but can generally be
    ignored in production.

4.  `INFO`

    Use this to provide extra information that is helpful for developers.

5.  `VERBOSE`

    Use this to provide even more information which may be helpful when tracing
    through execution in detail, such as when debugging test failures. This is
    the only level which should include any sensitive data.

Logging is done with the `dlog_*` macros, e.g. `dlog_info`. These accept
printf-style format strings and arguments.

The log level of a build is controlled by the `log_level` argument defined in
[`BUILDCONFIG.gn`](../../build/BUILDCONFIG.gn). This defaults to `INFO` for debug
builds and tests, meaning that all levels except `VERBOSE` will be logged. It is
recommended to set the log level to `NOTICE` for production builds, to reduce
binary size and log spam.
