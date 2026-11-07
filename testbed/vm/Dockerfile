# Testbed "VM": an old Debian with deliberately vulnerable packages.
# It installs the agent with the dashboard's own install.sh (cron path,
# since there is no systemd) exactly like a real host would.
# NEVER reuse these pins outside the testbed.
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl cron gzip procps \
 && rm -rf /var/lib/apt/lists/*
# Language manifests only: grype catalogs them, nothing is installed or run.
COPY app/ /opt/app/
# log4shell (CVE-2021-44228): a jar on disk is enough for grype to find it.
ADD https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar /opt/app/lib/log4j-core-2.14.1.jar
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
