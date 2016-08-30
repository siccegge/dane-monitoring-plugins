# Scope

The set of monitoring plugins in this repository is intended to serve
as icinga / nagios / .. checks for DANE enabled network services. The
central functionality therefore is checking whether the services
conforms with the DANE records. However, all service plugins are also
supposed to work as *the* plugin for each service and should be able
to monitor all relevant properties.

# Getting the Code

The main repository is located at [git.siccegge.de][1] but mirrors can
be found on both [GitLab][2] and [GitHub][3]. Pull request will be
processed by mail as well as on both platforms.

[1]: https://git.siccegge.de/?p=dane-monitoring-plugins.git
[2]: https://gitlab.com/siccegge/dane-monitoring-plugins
[3]: https://github.com/siccegge/dane-monitoring-plugins

# Dependencies

The plugins need `pyasn1`, `pyasn1-modules` and the python `unbound`
as well as python3. The `check_dnssec` module needs additionally the
python `ldns` module. Unfortunately the unbound package in Debian only
provides python2 modules currently. Building unbound with python3
support from source works fine however.

# License

Unfortunately the problems at hand tend to result in a dependency on
OpenSSL which makes plain GPL inviable. Until a proper decision is
made you can assume GPLv3 with OpenSSL exception
