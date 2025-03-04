FROM registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.24-openshift-4.20 AS builder
WORKDIR /go/src/github.com/openshift/secrets-store-csi-driver
COPY . .
RUN make bats helm kubectl yq && bats-core-*/install.sh bats

# "src" is built by a prow job when building final images.
# It contains full repository sources + jq + pyhon with yaml module.
FROM src
COPY --from=builder /go/src/github.com/openshift/secrets-store-csi-driver/bats /usr/local
COPY --from=builder /usr/local/bin/helm /usr/local/bin
COPY --from=builder /usr/local/bin/kubectl /usr/local/bin
COPY --from=builder /usr/local/bin/yq /usr/local/bin
