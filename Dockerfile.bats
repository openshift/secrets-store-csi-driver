FROM registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.23-openshift-4.19 AS builder
WORKDIR /go/src/github.com/openshift/secrets-store-csi-driver
COPY . .
ENV BATS_VERSION="1.12.0"
RUN make bats helm kubectl yq && bats-core-*/install.sh bats

# Install aws-cli
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
RUN unzip awscliv2.zip > /dev/null 2>&1
RUN ./aws/install
RUN aws --version

# "src" is built by a prow job when building final images.
# It contains full repository sources + jq + pyhon with yaml module.
FROM src
COPY --from=builder /go/src/github.com/openshift/secrets-store-csi-driver/bats /usr/local
COPY --from=builder /usr/local/bin/helm /usr/local/bin
COPY --from=builder /usr/local/bin/kubectl /usr/local/bin
COPY --from=builder /usr/local/bin/yq /usr/local/bin
COPY --from=builder /usr/local/aws-cli/ /usr/local/aws-cli/
RUN ln -s /usr/local/aws-cli/v2/current/bin/aws /usr/local/bin/aws
RUN aws --version

# Install envsubst and less
RUN dnf install -y gettext less && dnf clean all
