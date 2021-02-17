# How to Contribute

We'd love to accept your patches and contributions to this project. There are
just a few small guidelines you need to follow.

## Style guide

Submissions should follow the Hafnium [style guide](docs/StyleGuide.md).

## Code reviews

All submissions, including submissions by project members, require review. We
use [Gerrit](https://review.trustedfirmware.org/) for this purpose.

To submit a change:

1.  Create an account in the [Gerrit UI](https://review.trustedfirmware.org/).
2.  Follow the [getting started](docs/GettingStarted.md) instructions to clone
    the Hafnium repositories and set up the necessary commit hook.
3.  Make your change.
4.  Run our autoformatter with `make format`.
5.  Commit as usual. If you make a change in a submodule you will also need to
    commit a change in the main repository to update the submodule version.
6.  Ensure that each commit in the series has at least one `Signed-off-by:`
    line, using your real name and email address. The names in the
    `Signed-off-by:` and `Author:` lines must match. If anyone else contributes
    to the commit, they must also add their own `Signed-off-by:` line. By adding
    this line the contributor certifies the contribution is made under the terms
    of the [Developer Certificate of Origin](dco.txt). More details may be found
    in the
    [Gerrit Signed-off-by Lines guidelines](https://review.trustedfirmware.org/Documentation/user-signedoffby.html).
7.  Run the [tests](docs/Testing.md) and other presubmit checks with
    `kokoro/build.sh`, ensure they all pass.
8.  Upload the change to Gerrit with `git push origin HEAD:refs/for/master`. If
    you have changed submodules then you'll need to push them as well.
9.  If you changed submodules, then add a matching 'topic' from the Gerrit UI
    for all your changes (submodules and the main repository) so that they can
    be reviewed and submitted together.
10. Wait 20-30 minutes for the presubmit tests to run, and make sure a 'Verified
    +1' comment shows up in Gerrit indicating that they have passed. If not,
    follow the links to find the errors, fix them and try again.
11. From the Gerrit UI add one or more reviewers. Looking at who has modified
    the same files frequently recently is usually a good way to pick a reviewer.
    Add a maintainer listed in the [maintainers](docs/Maintainers.md) page, who
    will perform a final review and eventually approve the change.

## Community Guidelines

This project follows
[Google's Open Source Community Guidelines](https://opensource.google.com/conduct/).
