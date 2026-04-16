# PR2: RHCOS10 — Migrate Base Images from OCP/UBI9 to UBI10

## Purpose

Migrate all OpenShift Dockerfile base images from the OCP CI registry (RHEL9-based) to
`registry.redhat.io` UBI10 images, aligning with the RHCOS10 host OS.

This is the follow-up to PR1 (`rhcos10-ubi9-compat-test`), which validated that the
existing OCP/UBI9 images run correctly on RHCOS10 nodes. This PR adopts UBI10 as the
native base for RHCOS10 deployments.

## Background

Red Hat CoreOS 10 (RHCOS10) ships with RHEL10 as its host OS. Using UBI10-based images
ensures better alignment with the host OS libraries and security updates, and removes the
dependency on the OCP CI internal registry (`registry.ci.openshift.org`) for runtime
images.

## Changes

### Registry change

All OpenShift variant images move from the OCP CI registry to the authenticated Red Hat
registry:

```
registry.ci.openshift.org/ocp/builder:rhel-9-golang-*  →  registry.redhat.io/ubi10/go-toolset:10.1
registry.ci.openshift.org/ocp/4.20:base-rhel9           →  registry.redhat.io/ubi10:10.1
```

### Dockerfile changes

#### `Dockerfile.openshift` — main driver image

| Stage | Before | After |
|---|---|---|
| Builder | `registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.24-openshift-4.20` | `registry.redhat.io/ubi10/go-toolset:10.1` |
| Runtime | `registry.ci.openshift.org/ocp/4.20:base-rhel9` | `registry.redhat.io/ubi10:10.1` |

Additional change: added `USER 0` after the builder `FROM` line (required by
`go-toolset`) and `RUN dnf install -y util-linux ca-certificates && dnf clean all` in
the runtime stage.

#### `Dockerfile.e2eprovider` — e2e mock provider

| Stage | Before | After |
|---|---|---|
| Builder | `registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.24-openshift-4.20` | `registry.redhat.io/ubi10/go-toolset:10.1` |
| Runtime | `registry.ci.openshift.org/ocp/4.20:base-rhel9` | `registry.redhat.io/ubi10:10.1` |

#### `Dockerfile.bats` — bats test runner

| Stage | Before | After |
|---|---|---|
| Builder | `registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.24-openshift-4.20` | `registry.redhat.io/ubi10/go-toolset:10.1` |
| Runtime | `src` (prow-injected) | unchanged |

## Files NOT Changed

| File | Reason |
|---|---|
| `docker/Dockerfile` | Upstream community Dockerfile using `golang` + `debian-base` — not OCP-specific |
| `docker/crd.Dockerfile` | Uses `alpine` + `gcr.io/distroless/static` — not OCP-specific |
| `test/e2eprovider/Dockerfile` | Upstream community Dockerfile using `golang` + `gcr.io/distroless/static` |
| `.local/Dockerfile` | Local development debug image using `golang:alpine` — not for production |
| `vendor/` | Vendored dependency, not modified |

## Test Matrix

| Cluster OS | Driver image base | Expected result |
|---|---|---|
| RHCOS10 | UBI10 (this PR) | Pass — native RHEL10 base |
| RHCOS9  | UBI10 (this PR) | Pass — UBI10 containers are compatible with RHCOS9 |

## Test Plan

- [ ] `Dockerfile.openshift` builds successfully with `go-toolset:10.1` as builder and
  `ubi10:10.1` as runtime
- [ ] `Dockerfile.e2eprovider` builds successfully with `go-toolset:10.1` as builder and
  `ubi10:10.1` as runtime
- [ ] `Dockerfile.bats` builds successfully with `go-toolset:10.1` as builder
- [ ] CI jobs pass on RHCOS10 cluster nodes with UBI10 base images
- [ ] CI jobs pass on RHCOS9 cluster nodes with UBI10 base images (regression check)
- [ ] No regressions compared to UBI9 baseline (PR1)

## References

- [Red Hat UBI10 Container Catalog](https://catalog.redhat.com/en/software/containers/ubi10/ubi/66f2b46b122803e4937d11ae)
- [Red Hat UBI10 go-toolset Container Catalog](https://catalog.redhat.com/en/software/containers/ubi10/go-toolset)
- PR1 baseline: `docs/rhcos10-ubi9-compat-test.md`
