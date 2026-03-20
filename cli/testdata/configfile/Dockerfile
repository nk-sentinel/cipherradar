FROM ubuntu:22.04

# Unpinned openssl install — should be detected.
RUN apt-get update && apt-get install -y openssl curl

# TLS endpoint indicator — should be detected.
EXPOSE 443

# Another unpinned openssl install variant.
RUN apt install -y openssl libssl-dev

COPY app /usr/local/bin/app

# Non-TLS port — informational.
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/app"]
