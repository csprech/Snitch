# Security policy

Please report suspected vulnerabilities privately through GitHub's **Report a vulnerability** feature if enabled for this repository. Do not post exploit details or secrets in a public issue. Include the affected version, a minimal reproduction, and the security impact.

Snitch is an application level gateway. Its stop guarantee requires upstream tools and credentials to be inaccessible directly to monitored agents. Deploy with TLS, separate operator credentials, a protected database, and a restrictive network policy. Review model judgments are not a security boundary by themselves.
