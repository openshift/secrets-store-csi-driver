# PR1: RHCOS10 Compatibility Test — Existing OCP/UBI9 Images

## Purpose

This PR contains **no Dockerfile changes**. Its goal is to validate that the existing
OCP CI registry / UBI9-based images build and run correctly on an RHCOS10 cluster,
before committing to a full base-image migration.

## Background

Red Hat CoreOS 10 (RHCOS10) ships with RHEL10 as its host OS. While UBI9-based and
OCP-CI-registry-based container images are expected to remain compatible with RHCOS10
(containers are isolated from the host OS), this PR triggers CI against an RHCOS10
cluster to confirm there are no runtime surprises before we proceed with the UBI10
migration (see PR2).

## Images Under Test

All OpenShift-variant Dockerfiles currently reference OCP CI registry images pinned to
RHEL9/4.20:

| Image | Dockerfile | Builder | Runtime |
|---|---|---|---|
| secrets-store-csi | `Dockerfile.openshift` | `registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.24-openshift-4.20` | `registry.ci.openshift.org/ocp/4.20:base-rhel9` |
| bats test runner | `Dockerfile.bats` | `registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.24-openshift-4.20` | `src` (prow-injected) |
| e2e provider | `Dockerfile.e2eprovider` | `registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.24-openshift-4.20` | `registry.ci.openshift.org/ocp/4.20:base-rhel9` |

The upstream community Dockerfiles (`docker/Dockerfile`, `test/e2eprovider/Dockerfile`)
use standard `golang` and `gcr.io/distroless` images and are not in scope for this
migration.

## Test Matrix

| Cluster OS | Driver image base | Expected result |
|---|---|---|
| RHCOS10 | OCP/UBI9 (unchanged) | Pass — containers are OS-isolated |
| RHCOS9  | OCP/UBI9 (unchanged) | Pass — existing baseline |

## Expected Outcome

- All existing CI jobs pass on RHCOS10 nodes with the current OCP/UBI9 base images
  unchanged.
- No runtime incompatibilities between UBI9/RHEL9-built containers and the RHCOS10 host.

## Follow-up

If this PR passes, PR2 (`rhcos10-ubi10-migration`) migrates all OpenShift Dockerfile
base images to UBI10, which is the native base for RHCOS10.
