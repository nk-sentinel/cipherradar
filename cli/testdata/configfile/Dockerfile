FROM ubuntu:22.04

# Unpinned openssl install — should be detected.
RUN apt-get update && apt-get install -y openssl curl

# TLS endpoint indicator — should be detected.
EXPOSE 443

# Another unpinned openssl install variant.
RUN apt install -y openssl libssl-dev

# Alpine apk install of openssl — should be detected.
RUN apk add --no-cache openssl

# RHEL/Fedora install of openssl — should be detected.
RUN dnf install -y openssl

# Crypto dev library only — should be detected as crypto library install.
RUN apt-get install -y libssl-dev

# Pinned openssl install — should NOT be detected.
RUN apk add openssl=3.0.2-r0

COPY app /usr/local/bin/app

# Non-TLS port — informational.
EXPOSE 8080

# Alternate TLS port — should be detected.
EXPOSE 8443/tcp

ENTRYPOINT ["/usr/local/bin/app"]
