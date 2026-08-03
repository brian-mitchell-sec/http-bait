# Security and data-removal contact

## Reporting a vulnerability in this code

Preferred: GitHub's private advisory flow,
**Security → Report a vulnerability** on
<https://github.com/brian-mitchell-sec/http-bait/security/advisories/new>.
That keeps the report private until there is a fix.

By email: **security@brianmitchell.ai**.

Please include the commit or tag you tested, how to reproduce, and what you
think the impact is. There is no bounty here; this is a personal research
project.

## What is in scope

This is a honeypot. It is *supposed* to look vulnerable, serve fake secrets, and
attract exploit attempts. Those are features.

In scope:

- Anything that makes the service execute, query, fetch, or act on caller input.
  Nothing here should ever do that. See [SPEC.md](SPEC.md) §2.
- Anything that turns it into a DoS amplifier or reflector.
- Anything that causes it to retain a visitor's credentials or other secrets in
  the log. See [DATA-HANDLING.md](DATA-HANDLING.md).
- Anything that lets a remote caller stop collection: filling the disk, wedging
  the event loop, or silencing the writer while the service still answers.
- Anything that leaks operator detail (paths, disk figures, real hostnames)
  through a response body or header.

Not in scope:

- The fake secrets are fake. They are honeytokens, not credentials.
- The advertised versions are false on purpose.
- Missing security headers, absent rate limiting on non-collection paths, and
  similar findings against a service that is deliberately presenting as an
  outdated, poorly-maintained host.

## Data removal

If you scanned a host running this and want records associated with your address
removed, email **security@brianmitchell.ai** or open a private advisory, with the
address and an approximate time range. A removal request should not require a
GitHub account.

Published material truncates third-party addresses to /24, and raw logs are not
published. See [DATA-HANDLING.md](DATA-HANDLING.md) for exactly what is recorded
and what is discarded.

## If you are running this yourself

You are the operator and the contact, not this repository. Read
[DATA-HANDLING.md](DATA-HANDLING.md) before deploying, put a real contact in
your own copy, and give the service its own host and a hostname with no
association to anything else you run.
