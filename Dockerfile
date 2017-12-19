FROM fedora:latest

RUN yum update; yum install vim dnsmasq bash NetworkManager NetworkManager-wifi dbus wireless-tools -y;

# Install jq
RUN JQ_URL="https://circle-downloads.s3.amazonaws.com/circleci-images/cache/linux-amd64/jq-latest" \
    && curl --silent --show-error --location --fail --retry 3 --output /usr/bin/jq $JQ_URL \
    && chmod +x /usr/bin/jq \
    && jq --version

VOLUME /work
WORKDIR /work
COPY src src
COPY scripts scripts
COPY public public
COPY Cargo.toml Cargo.toml
COPY rustfmt.toml rustfmt.toml
COPY start start
COPY target target

RUN usermod --password '' root
RUN systemctl unmask console-getty.service
RUN mkdir -p /etc/systemd/system/default.target.wants
RUN ln -sf /usr/lib/systemd/system/console-getty.service /etc/systemd/system/default.target.wants/console-getty.service

EXPOSE 80 53
CMD ["/bin/bash"]
