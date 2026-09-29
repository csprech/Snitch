# Contributing

Snitch controls tool execution, so changes to authorization, approval, idempotency, or alerting need a test that shows both the allowed path and the denied path. Open an issue with the threat model and expected behavior before large design changes. Keep dependencies minimal, avoid logging raw credentials, and document any new external side effect.

Run `python3 -m unittest discover -s tests -v` before submitting a pull request. Do not include real agent tokens, API keys, or customer data in fixtures.
