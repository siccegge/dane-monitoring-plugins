# Getting the Code

The main repository is located at [git.siccegge.de][1] but mirrors can
be found on both [GitLab][2] and [GitHub][3]. Pull request will be
processed by mail as well as on both platforms.

[1]: https://git.siccegge.de/?p=dane-monitoring-plugins.git
[2]: https://gitlab.com/siccegge/dane-monitoring-plugins
[3]: https://github.com/siccegge/dane-monitoring-plugins

# Dependencies

The plugins need pyasn1, pyasn1-modules and pyunbound as well as
python3. Unfortunately the unbound package in Debian only provides
python2 modules currently. Building pyunbound from source works fine
however.

# License

Unfortunately the problems at hand tend to result in a dependency on
OpenSSL which makes plain GPL inviable. Until a proper decision is
made you can assume GPLv3 with OpenSSL exception
