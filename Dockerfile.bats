FROM registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.24-openshift-4.20 AS builder
WORKDIR /go/src/github.com/openshift/secrets-store-csi-driver
COPY . .
ENV BATS_VERSION="1.12.0"
RUN make bats helm kubectl yq && bats-core-*/install.sh bats

# Install aws-cli
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
RUN unzip awscliv2.zip > /dev/null 2>&1
RUN ./aws/install
RUN aws --version

# Install gcloud cli
RUN curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-x86_64.tar.gz
RUN tar -xf google-cloud-cli-linux-x86_64.tar.gz
RUN ./google-cloud-sdk/install.sh
RUN ./google-cloud-sdk/bin/gcloud version

# "src" is built by a prow job when building final images.
# It contains full repository sources + jq + pyhon with yaml module.
FROM src
COPY --from=builder /go/src/github.com/openshift/secrets-store-csi-driver/bats /usr/local
COPY --from=builder /usr/local/bin/helm /usr/local/bin
COPY --from=builder /usr/local/bin/kubectl /usr/local/bin
COPY --from=builder /usr/local/bin/yq /usr/local/bin

# Copy aws-cli
COPY --from=builder /usr/local/aws-cli/ /usr/local/aws-cli/
RUN ln -s /usr/local/aws-cli/v2/current/bin/aws /usr/local/bin/aws
RUN aws --version

# Copy gcloud cli
COPY --from=builder /go/src/github.com/openshift/secrets-store-csi-driver/google-cloud-sdk/ /usr/local/google-cloud-sdk/
RUN ln -s /usr/local/google-cloud-sdk/bin/gcloud /usr/local/bin/gcloud
RUN gcloud version

# Install envsubst and less
RUN dnf install -y gettext less && dnf clean all
