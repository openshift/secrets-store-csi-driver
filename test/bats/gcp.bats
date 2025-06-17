#!/usr/bin/env bats

load helpers

BATS_TESTS_DIR=test/bats/tests/gcp
WAIT_TIME=60
SLEEP_TIME=1
NAMESPACE=default
PROVIDER_NAMESPACE=kube-system
PROVIDER_YAML=https://raw.githubusercontent.com/GoogleCloudPlatform/secrets-store-csi-driver-provider-gcp/main/deploy/provider-gcp-plugin.yaml
BASE64_FLAGS="-w 0"


setup_file() {
  export SECRET_VALUE="secret-a"
  export GCP_PROVIDER=gcp-provider.yaml
  export RANDOM_NUM=$(echo $RANDOM | md5sum | head -c 8)
  export SECRET_ID=test-secret-$RANDOM_NUM
  export FILE_NAME=testsecret1.txt
  export GCP_PROJECT_ID=$(gcloud config get-value project)
  export GCP_PROJECT_NUM=$(gcloud projects describe $(gcloud config get-value project) --format="value(projectNumber)")
  export RESOURCE_NAME=projects/$GCP_PROJECT_ID/secrets/$SECRET_ID/versions/latest
  export GCP_WORKLOAD_IDENTITY_POOL=wif-pool-$RANDOM_NUM
  export GCP_WORKLOAD_IDENTITY_PROVIDER=$GCP_WORKLOAD_IDENTITY_POOL-oidc
  export LOCATION="global"
  export AUDIENCE=//iam.googleapis.com/projects/$GCP_PROJECT_NUM/locations/$LOCATION/workloadIdentityPools/$GCP_WORKLOAD_IDENTITY_POOL/providers/$GCP_WORKLOAD_IDENTITY_PROVIDER

  #create gcp workload identity pool and provider
  OIDC_ISSUER=$(kubectl get --raw /.well-known/openid-configuration | jq -r .issuer )
  kubectl get --raw /openid/v1/jwks > cluster-jwks.json

  gcloud iam workload-identity-pools create $GCP_WORKLOAD_IDENTITY_POOL     --location="$LOCATION"     --description="$GCP_WORKLOAD_IDENTITY_POOL"     --display-name="$GCP_WORKLOAD_IDENTITY_POOL"

  gcloud iam workload-identity-pools providers create-oidc $GCP_WORKLOAD_IDENTITY_PROVIDER     --location="$LOCATION"     --workload-identity-pool=$GCP_WORKLOAD_IDENTITY_POOL     --issuer-uri=$OIDC_ISSUER     --attribute-mapping="google.subject=assertion.sub"     --jwk-json-path="cluster-jwks.json"

  gcloud iam workload-identity-pools create-cred-config     projects/$GCP_PROJECT_NUM/locations/$LOCATION/workloadIdentityPools/$GCP_WORKLOAD_IDENTITY_POOL/providers/$GCP_WORKLOAD_IDENTITY_PROVIDER     --credential-source-file=/var/run/service-account/token     --credential-source-type=text     --output-file=credential-configuration.json

  #create a configmap with credenital-configuration.json
  oc create configmap gcp-cred-cm   --from-file credential-configuration.json -n $PROVIDER_NAMESPACE
  rm credential-configuration.json

  #create a secret
  echo "$SECRET_VALUE" > secret.data
  echo "SECRET_ID: $SECRET_ID"
  gcloud secrets create $SECRET_ID --replication-policy=automatic --data-file=secret.data
  rm secret.data

  sleep 10
  #give permission to default service account to be able to access the secret
  gcloud secrets add-iam-policy-binding $SECRET_ID --member="principal://iam.googleapis.com/projects/$GCP_PROJECT_NUM/locations/$LOCATION/workloadIdentityPools/$GCP_WORKLOAD_IDENTITY_POOL/subject/system:serviceaccount:default:default" --role=roles/secretmanager.secretAccessor
  sleep 20
}

@test "install gcp provider" {
  #run kubectl apply -f $PROVIDER_YAML --namespace $PROVIDER_NAMESPACE

  run kubectl apply -f $BATS_TESTS_DIR/$GCP_PROVIDER
  oc adm policy add-scc-to-user privileged -z csi-secrets-store-provider-gcp -n openshift-cluster-csi-drivers
  assert_success

  kubectl wait --for=condition=Ready --timeout=120s pod -l app=csi-secrets-store-provider-gcp --namespace $PROVIDER_NAMESPACE

  GCP_PROVIDER_POD=$(kubectl get pod --namespace $PROVIDER_NAMESPACE -l app=csi-secrets-store-provider-gcp -o jsonpath="{.items[0].metadata.name}")

  run kubectl get pod/$GCP_PROVIDER_POD --namespace $PROVIDER_NAMESPACE
  assert_success
}

@test "deploy gcp secretproviderclass crd" {
  envsubst < $BATS_TESTS_DIR/gcp_v1_secretproviderclass.yaml | kubectl apply --namespace=$NAMESPACE -f -

  cmd="kubectl get secretproviderclasses.secrets-store.csi.x-k8s.io/gcp --namespace=$NAMESPACE -o yaml | grep gcp"
  wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"
}

@test "CSI inline volume test with pod portability" {
  envsubst < $BATS_TESTS_DIR/pod-secrets-store-inline-volume-crd.yaml | kubectl apply --namespace=$NAMESPACE -f -

  kubectl wait --for=condition=Ready --timeout=60s --namespace=$NAMESPACE pod/secrets-store-inline-crd

  run kubectl get pod/secrets-store-inline-crd --namespace=$NAMESPACE
  assert_success
}

@test "CSI inline volume test with pod portability - read gcp kv secret from pod" {
  archive_info
  result=$(kubectl exec secrets-store-inline-crd --namespace=$NAMESPACE -- cat /mnt/secrets-store/$FILE_NAME)
  [[ "${result//$'\r'}" == "${SECRET_VALUE}" ]]

}

@test "CSI inline volume test with rotation - read gcp kv secret from pod" {
  echo -n "secret-b" | gcloud secrets versions add ${SECRET_ID} --data-file=-

  # wait for secret rotation
  sleep 180
  archive_info
  result=$(kubectl exec secrets-store-inline-crd --namespace=$NAMESPACE -- cat /mnt/secrets-store/$FILE_NAME)
  [[ "${result//$'\r'}" == "secret-b" ]]

}

@test "CSI inline volume test with pod portability - unmount succeeds" {
  # On Linux a failure to unmount the tmpfs will block the pod from being
  # deleted.
  run kubectl delete pod secrets-store-inline-crd --namespace=$NAMESPACE
  assert_success

  run kubectl wait --for=delete --timeout=${WAIT_TIME}s --namespace=$NAMESPACE pod/secrets-store-inline-crd
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

teardown_file() {
  #delete configmap
  oc delete cm gcp-cred-cm -n $PROVIDER_NAMESPACE

  run kubectl delete -f $BATS_TESTS_DIR/$GCP_PROVIDER

  #delete secret
  gcloud secrets delete $SECRET_ID --quiet

  #delete workload identity pool and provider
  gcloud iam workload-identity-pools providers delete $GCP_WORKLOAD_IDENTITY_PROVIDER \
    --workload-identity-pool=$GCP_WORKLOAD_IDENTITY_POOL \
    --location=$LOCATION \
    --project=$GCP_PROJECT_ID \
    --quiet

  gcloud iam workload-identity-pools delete $GCP_WORKLOAD_IDENTITY_POOL \
    --location=$LOCATIONl \
    --project=$GCP_PROJECT_ID \
    --quiet

  archive_provider "app=csi-secrets-store-provider-gcp" || true
  archive_info || true
}
