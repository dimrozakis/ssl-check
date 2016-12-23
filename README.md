# ssl-check

Command line tool to check the validity of SSL/TLS certificates using
[SSL Labs Test](https://www.ssllabs.com/ssltest/). Prints useful information
about the certificates of each host. Exits with error if the tests fail, the
hostname can't be resolved or the host is unreachable. Can optionally be
configured to fail if certificate is about to expire, or if it got a bad grade
by the SSL Labs test.

The python dependencies are `requests` and `prettytable`.

Run `ssl-check --help` to see a detailed list of options.
