#!/usr/bin/env bats

load helpers

BATS_TESTS_DIR=test/bats/tests/vault
WAIT_TIME=120
SLEEP_TIME=1

export LABEL_VALUE=${LABEL_VALUE:-"test"}
export ANNOTATION_VALUE=${ANNOTATION_VALUE:-"app=test"}

@test "install vault provider" {
  # create the ns vault

  oc delete project vault --ignore-not-found=true
  kubectl create ns vault
  kubectl label ns vault security.openshift.io/scc.podSecurityLabelSync=false pod-security.kubernetes.io/enforce=privileged pod-security.kubernetes.io/audit=privileged pod-security.kubernetes.io/warn=privileged --overwrite
  oc adm policy add-scc-to-user privileged system:serviceaccount:vault:vault
  oc adm policy add-scc-to-user privileged system:serviceaccount:vault:vault-csi-provider

  # install the vault provider using the helm charts
  # pinning this to a fixed version (1.7.0)
  helm repo add hashicorp https://helm.releases.hashicorp.com
  helm repo update
  helm install vault hashicorp/vault --namespace=vault \
        --set "server.dev.enabled=true" \
        --set "injector.enabled=false" \
        --set "csi.enabled=true" \
        --set "global.openshift=true" \
        --set "injector.agentImage.repository=docker.io/hashicorp/vault" \
        --set "server.image.repository=docker.io/hashicorp/vault" \
        --set "csi.image.repository=docker.io/hashicorp/vault-csi-provider" \
        --set "csi.agent.image.repository=docker.io/hashicorp/vault" \
        --set "csi.daemonSet.providersDir=/var/run/secrets-store-csi-providers"
  oc patch daemonset -n vault vault-csi-provider --type='json' -p='[{"op": "add", "path": "/spec/template/spec/containers/0/securityContext", "value": {"privileged": true} }]'
  sleep 10 

  # wait for vault and vault-csi-provider pods to be running
  oc wait --for=jsonpath=.status.readyReplicas=1 --timeout=120s statefulset/vault -n vault
  num_pods_scheduled=$(oc get daemonset/vault-csi-provider -n vault -o jsonpath='{.status.desiredNumberScheduled}')
  oc wait --for=jsonpath=.status.numberReady=${num_pods_scheduled} --timeout=120s daemonset/vault-csi-provider -n vault
}

@test "setup vault" {
  # create the kv pair in vault
  kubectl exec vault-0 --namespace=vault -- vault kv put secret/foo bar=hello
  kubectl exec vault-0 --namespace=vault -- vault kv put secret/foo1 bar1=hello1

  # enable authentication
  kubectl exec vault-0 --namespace=vault -- vault auth enable kubernetes

  local token_reviewer_jwt="$(kubectl exec vault-0 --namespace=vault -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
  local kubernetes_service_ip="$(kubectl get svc kubernetes -o go-template="{{ .spec.clusterIP }}")"
  # enable authentication using the kubernetes service token from vault pod
  kubectl exec -i vault-0 --namespace=vault -- vault write auth/kubernetes/config \
    issuer="https://kubernetes.default.svc.cluster.local" \
    token_reviewer_jwt="${token_reviewer_jwt}" \
    kubernetes_host="https://${kubernetes_service_ip}:443" \
    kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

  # create vault policy to allow access to created secrets
  kubectl exec -i vault-0 --namespace=vault -- vault policy write csi -<<EOF
path "secret/data/*" {
 capabilities = ["read"]
}
EOF

  # create authentication role
  kubectl exec -i vault-0 --namespace=vault -- vault write auth/kubernetes/role/csi \
    bound_service_account_names=default \
    bound_service_account_namespaces=default,test-ns,negative-test-ns \
    policies=csi \
    ttl=20m
}

@test "deploy vault secretproviderclass crd" {
  kubectl apply -f $BATS_TESTS_DIR/vault_v1_secretproviderclass.yaml
  kubectl wait --for condition=established --timeout=60s crd/secretproviderclasses.secrets-store.csi.x-k8s.io

  cmd="kubectl get secretproviderclasses.secrets-store.csi.x-k8s.io/vault-foo -o yaml | grep vault"
  wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"
}

@test "CSI inline volume test with pod portability" {
  kubectl apply -f $BATS_TESTS_DIR/pod-vault-inline-volume-secretproviderclass.yaml
  # wait for pod to be running
  kubectl wait --for=condition=Ready --timeout=60s pod/secrets-store-inline

  run kubectl get pod/secrets-store-inline
  assert_success
}

@test "CSI inline volume test with pod portability - read vault secret from pod" {
  result=$(kubectl exec secrets-store-inline -- cat /mnt/secrets-store/bar)
  [[ "$result" == "hello" ]]

  result=$(kubectl exec secrets-store-inline -- cat /mnt/secrets-store/bar1)
  [[ "$result" == "hello1" ]]
}

@test "CSI inline volume test with pod portability - rotation succeeds" {
  # seed first value
  kubectl exec vault-0 --namespace=vault -- vault kv put secret/rotation foo=start

  # deploy pod
  kubectl apply -f $BATS_TESTS_DIR/pod-vault-rotation.yaml
  kubectl wait --for=condition=Ready --timeout=60s pod/secrets-store-rotation

  run kubectl get pod/secrets-store-rotation
  assert_success

  # verify starting value
  result=$(kubectl exec secrets-store-rotation -- cat /mnt/secrets-store/foo)
  [[ "$result" == "start" ]]

  # update the secret value
  kubectl exec vault-0 --namespace=vault -- vault kv put secret/rotation foo=rotated

  sleep 120

  # verify rotated value
  result=$(kubectl exec secrets-store-rotation -- cat /mnt/secrets-store/foo)
  [[ "$result" == "rotated" ]]
}

@test "CSI inline volume test with pod portability - unmount succeeds" {
  # On Linux a failure to unmount the tmpfs will block the pod from being
  # deleted.
  run kubectl delete pod secrets-store-inline
  assert_success

  run kubectl wait --for=delete --timeout=${WAIT_TIME}s pod/secrets-store-inline
  assert_success

  # Sleep to allow time for logs to propagate.
  sleep 10

  # save debug information to archive in case of failure
  archive_info

  # On Windows, the failed unmount calls from: https://github.com/kubernetes-sigs/secrets-store-csi-driver/pull/545
  # do not prevent the pod from being deleted. Search through the driver logs
  # for the error.
  run bash -c "kubectl logs -l app=secrets-store-csi-driver --tail -1 -c secrets-store -n kube-system | grep '^E.*failed to clean and unmount target path.*$'"
  assert_failure
}

@test "Sync with K8s secrets - create deployment" {
  kubectl apply -f $BATS_TESTS_DIR/vault_synck8s_v1_secretproviderclass.yaml
  kubectl wait --for condition=established --timeout=60s crd/secretproviderclasses.secrets-store.csi.x-k8s.io

  cmd="kubectl get secretproviderclasses.secrets-store.csi.x-k8s.io/vault-foo-sync -o yaml | grep vault"
  wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"

  run kubectl apply -f $BATS_TESTS_DIR/deployment-synck8s.yaml
  assert_success

  run kubectl apply -f $BATS_TESTS_DIR/deployment-two-synck8s.yaml
  assert_success

  kubectl wait --for=condition=Ready --timeout=120s pod -l app=busybox
}

@test "Sync with K8s secrets - read secret from pod, read K8s secret, read env var, check secret ownerReferences with multiple owners" {
  POD=$(kubectl get pod -l app=busybox -o jsonpath="{.items[0].metadata.name}")
  result=$(kubectl exec $POD -- cat /mnt/secrets-store/bar)
  [[ "$result" == "hello" ]]

  result=$(kubectl exec $POD -- cat /mnt/secrets-store/bar1)
  [[ "$result" == "hello1" ]]

  result=$(kubectl exec $POD -- cat /mnt/secrets-store/nested/bar)
  [[ "$result" == "hello" ]]

  result=$(kubectl get secret foosecret -o jsonpath="{.data.pwd}" | base64 -d)
  [[ "$result" == "hello" ]]

  result=$(kubectl get secret foosecret -o jsonpath="{.data.nested}" | base64 -d)
  [[ "$result" == "hello" ]]

  result=$(kubectl exec $POD -- printenv | grep SECRET_USERNAME | awk -F"=" '{ print $2 }' | tr -d '\r\n')
  [[ "$result" == "hello1" ]]

  result=$(kubectl get secret foosecret -o jsonpath="{.metadata.labels.environment}")
  [[ "${result//$'\r'}" == "${LABEL_VALUE}" ]]

  result=$(kubectl get secret foosecret -o jsonpath="{.metadata.annotations.kubed\.appscode\.com\/sync}")
  [[ "${result//$'\r'}" == "${ANNOTATION_VALUE}" ]]

  result=$(kubectl get secret foosecret -o jsonpath="{.metadata.labels.secrets-store\.csi\.k8s\.io/managed}")
  [[ "${result//$'\r'}" == "true" ]]

  run wait_for_process $WAIT_TIME $SLEEP_TIME "compare_owner_count foosecret default 2"
  assert_success
}

@test "Sync with K8s secrets - delete deployment, check secret is deleted" {
  run kubectl delete -f $BATS_TESTS_DIR/deployment-synck8s.yaml
  assert_success
  
  run wait_for_process $WAIT_TIME $SLEEP_TIME "compare_owner_count foosecret default 1"
  assert_success

  run kubectl delete -f $BATS_TESTS_DIR/deployment-two-synck8s.yaml
  assert_success

  run wait_for_process $WAIT_TIME $SLEEP_TIME "check_secret_deleted foosecret default"
  assert_success

  run kubectl delete -f $BATS_TESTS_DIR/vault_synck8s_v1_secretproviderclass.yaml
  assert_success
}

@test "Test Namespaced scope SecretProviderClass - create deployment" {
  oc delete project test-ns --ignore-not-found=true
  kubectl create ns test-ns
  kubectl label ns test-ns security.openshift.io/scc.podSecurityLabelSync=false pod-security.kubernetes.io/enforce=privileged pod-security.kubernetes.io/audit=privileged pod-security.kubernetes.io/warn=privileged --overwrite

  kubectl apply -f $BATS_TESTS_DIR/vault_v1_secretproviderclass_ns.yaml
  kubectl wait --for condition=established --timeout=60s crd/secretproviderclasses.secrets-store.csi.x-k8s.io

  cmd="kubectl get secretproviderclasses.secrets-store.csi.x-k8s.io/vault-foo-sync -o yaml | grep vault"
  wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"

  cmd="kubectl get secretproviderclasses.secrets-store.csi.x-k8s.io/vault-foo-sync -n test-ns -o yaml | grep vault"
  wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"

  kubectl apply -n test-ns -f $BATS_TESTS_DIR/deployment-synck8s.yaml

  kubectl wait --for=condition=Ready --timeout=90s pod -l app=busybox -n test-ns
}

@test "Test Namespaced scope SecretProviderClass - Sync with K8s secrets - read secret from pod, read K8s secret, read env var, check secret ownerReferences" {
  POD=$(kubectl get pod -l app=busybox -n test-ns -o jsonpath="{.items[0].metadata.name}")
  result=$(kubectl exec -n test-ns $POD -- cat /mnt/secrets-store/bar)
  [[ "$result" == "hello" ]]

  result=$(kubectl exec -n test-ns $POD -- cat /mnt/secrets-store/bar1)
  [[ "$result" == "hello1" ]]

  result=$(kubectl get secret foosecret -n test-ns -o jsonpath="{.data.pwd}" | base64 -d)
  [[ "$result" == "hello" ]]

  result=$(kubectl exec -n test-ns $POD -- printenv | grep SECRET_USERNAME | awk -F"=" '{ print $2 }' | tr -d '\r\n')
  [[ "$result" == "hello1" ]]

  run wait_for_process $WAIT_TIME $SLEEP_TIME "compare_owner_count foosecret test-ns 1"
  assert_success
}

@test "Test Namespaced scope SecretProviderClass - Sync with K8s secrets - delete deployment, check secret deleted" {
  run kubectl delete -f $BATS_TESTS_DIR/deployment-synck8s.yaml -n test-ns
  assert_success

  run wait_for_process $WAIT_TIME $SLEEP_TIME "check_secret_deleted foosecret test-ns"
  assert_success
}

@test "Test Namespaced scope SecretProviderClass - Should fail when no secret provider class in same namespace" {
  oc delete project negative-test-ns --ignore-not-found=true
  kubectl create ns negative-test-ns
  kubectl label ns negative-test-ns security.openshift.io/scc.podSecurityLabelSync=false pod-security.kubernetes.io/enforce=privileged pod-security.kubernetes.io/audit=privileged pod-security.kubernetes.io/warn=privileged --overwrite

  kubectl apply -n negative-test-ns -f $BATS_TESTS_DIR/deployment-synck8s.yaml

  # wait for pod to be created
  kubectl wait --for=jsonpath='{.status.replicas}'=2 deployment -l app=busybox -n negative-test-ns --timeout=60s
  POD=$(kubectl get pod -l app=busybox -n negative-test-ns -o jsonpath="{.items[0].metadata.name}")
  cmd="kubectl describe pod $POD -n negative-test-ns | grep 'FailedMount.*failed to get secretproviderclass negative-test-ns/vault-foo-sync.*not found'"
  wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"

  run kubectl delete -f $BATS_TESTS_DIR/deployment-synck8s.yaml -n negative-test-ns
  assert_success

  run kubectl delete ns negative-test-ns
  assert_success
}

@test "deploy multiple vault secretproviderclass crd" {
  kubectl apply -f $BATS_TESTS_DIR/vault_v1_multiple_secretproviderclass.yaml

  cmd="kubectl wait --for condition=established --timeout=60s crd/secretproviderclasses.secrets-store.csi.x-k8s.io"
  wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"

  cmd="kubectl get secretproviderclasses.secrets-store.csi.x-k8s.io/vault-foo-sync-0 -o yaml | grep vault-foo-sync-0"
  wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"

  cmd="kubectl get secretproviderclasses.secrets-store.csi.x-k8s.io/vault-foo-sync-1 -o yaml | grep vault-foo-sync-1"
  wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"
}

@test "deploy pod with multiple secret provider class" {
  kubectl apply -f $BATS_TESTS_DIR/pod-vault-inline-volume-multiple-spc.yaml
  kubectl wait --for=condition=Ready --timeout=90s pod/secrets-store-inline-multiple-crd

  run kubectl get pod/secrets-store-inline-multiple-crd
  assert_success
}

@test "CSI inline volume test with multiple secret provider class" {
  result=$(kubectl exec secrets-store-inline-multiple-crd -- cat /mnt/secrets-store-0/bar)
  [[ "$result" == "hello" ]]

  result=$(kubectl exec secrets-store-inline-multiple-crd -- cat /mnt/secrets-store-0/bar1)
  [[ "$result" == "hello1" ]]

  result=$(kubectl get secret foosecret-0 -o jsonpath="{.data.pwd}" | base64 -d)
  [[ "$result" == "hello" ]]

  result=$(kubectl exec secrets-store-inline-multiple-crd -- printenv | grep SECRET_USERNAME_0 | awk -F"=" '{ print $2 }' | tr -d '\r\n')
  [[ "$result" == "hello1" ]]

  run wait_for_process $WAIT_TIME $SLEEP_TIME "compare_owner_count foosecret-0 default 1"
  assert_success

  result=$(kubectl exec secrets-store-inline-multiple-crd -- cat /mnt/secrets-store-1/bar)
  [[ "$result" == "hello" ]]

  result=$(kubectl exec secrets-store-inline-multiple-crd -- cat /mnt/secrets-store-1/bar1)
  [[ "$result" == "hello1" ]]

  result=$(kubectl get secret foosecret-1 -o jsonpath="{.data.pwd}" | base64 -d)
  [[ "$result" == "hello" ]]

  result=$(kubectl exec secrets-store-inline-multiple-crd -- printenv | grep SECRET_USERNAME_1 | awk -F"=" '{ print $2 }' | tr -d '\r\n')
  [[ "$result" == "hello1" ]]

  run wait_for_process $WAIT_TIME $SLEEP_TIME "compare_owner_count foosecret-1 default 1"
  assert_success
}

teardown_file() {
  archive_info || true
}
