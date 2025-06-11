#!/usr/bin/env bats

load helpers

WAIT_TIME=120
SLEEP_TIME=1
PROVIDER_YAML=https://raw.githubusercontent.com/aws/secrets-store-csi-driver-provider-aws/main/deployment/aws-provider-installer.yaml
export NAMESPACE="sscsi-namespace"
POD_NAME=basic-test-mount
export REGION=${REGION:-us-west-2}

export ACCOUNT_NUMBER=$(aws --region $REGION  sts get-caller-identity --query Account --output text)
export AWS_USER_NAME=$(aws sts get-caller-identity --query 'Arn' --output text | cut -d'/' -f2)
export CSI_DRIVER_INSTALLED_NAMESPACE=${CSI_DRIVER_INSTALLED_NAMESPACE:-"kube-system"}
export CLUSTER_NAME=$(oc get infrastructure cluster -o=jsonpath='{.status.infrastructureName}')
export OIDC_PROVIDER=$(oc get authentication.config.openshift.io cluster -o jsonpath='{.spec.serviceAccountIssuer}' | sed -e 's/^https\?:\/\///')

BATS_TEST_DIR=test/bats/tests/aws

if [ -z "$UUID" ]; then 
   export UUID=secret-$(openssl rand -hex 6) 
fi 

export SM_TEST_1_NAME=SecretsManagerTest1-$UUID 
export SM_TEST_2_NAME=SecretsManagerTest2-$UUID
export SM_SYNC_NAME=SecretsManagerSync-$UUID
export SM_ROT_TEST_NAME=SecretsManagerRotationTest-$UUID

export PM_TEST_1_NAME=ParameterStoreTest1-$UUID
export PM_TEST_LONG_NAME=ParameterStoreTestWithLongName-$UUID
export PM_ROTATION_TEST_NAME=ParameterStoreRotationTest-$UUID

setup_file() {

  export AWS_USER_PAS_POLICY="${CLUSTER_NAME:0:12}-ParameterAndSecret-access-${UUID}"
  export CSI_APP_ROLE_NAME="${CLUSTER_NAME:0:12}-csi-app-role-${UUID}"
  export CSI_APP_POLICY_NAME="${CLUSTER_NAME:0:12}-csi-app-policy-${UUID}"

  cat > $BATS_TEST_DIR/aws-user-pas-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowPutGetDeleteSpecificSSMParameters",
      "Effect": "Allow",
      "Action": [
        "ssm:PutParameter",
        "ssm:GetParameter",
        "ssm:DeleteParameter"
      ],
      "Resource": [
        "arn:aws:ssm:${REGION}:${ACCOUNT_NUMBER}:parameter/${PM_TEST_1_NAME}",
        "arn:aws:ssm:${REGION}:${ACCOUNT_NUMBER}:parameter/${PM_TEST_LONG_NAME}",
        "arn:aws:ssm:${REGION}:${ACCOUNT_NUMBER}:parameter/${PM_ROTATION_TEST_NAME}"
      ]
    },
    {
      "Sid": "AllowCreateGetDeleteSpecificSecrets",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:CreateSecret",
        "secretsmanager:GetSecretValue",
        "secretsmanager:DeleteSecret",
        "secretsmanager:PutSecretValue"
      ],
      "Resource": [
        "arn:aws:secretsmanager:${REGION}:${ACCOUNT_NUMBER}:secret:${SM_TEST_1_NAME}*",
        "arn:aws:secretsmanager:${REGION}:${ACCOUNT_NUMBER}:secret:${SM_TEST_2_NAME}*",
        "arn:aws:secretsmanager:${REGION}:${ACCOUNT_NUMBER}:secret:${SM_SYNC_NAME}*",
        "arn:aws:secretsmanager:${REGION}:${ACCOUNT_NUMBER}:secret:${SM_ROT_TEST_NAME}*"
      ]
    }
  ]
}
EOF

  PAS_POLICY=$(aws iam create-policy --policy-name "${AWS_USER_PAS_POLICY}" \
  --policy-document file://$BATS_TEST_DIR/aws-user-pas-policy.json \
  --query 'Policy.Arn' --output text)

  aws iam attach-user-policy --user-name $AWS_USER_NAME --policy-arn $PAS_POLICY

  #Create test secrets
  aws secretsmanager create-secret --name $SM_TEST_1_NAME --secret-string SecretsManagerTest1Value --region $REGION
  aws secretsmanager create-secret --name $SM_TEST_2_NAME --secret-string SecretsManagerTest2Value --region $REGION
  aws secretsmanager create-secret --name $SM_SYNC_NAME --secret-string SecretUser --region $REGION

  aws ssm put-parameter --name $PM_TEST_1_NAME --value ParameterStoreTest1Value --type SecureString --region $REGION
  aws ssm put-parameter --name $PM_TEST_LONG_NAME --value ParameterStoreTest2Value --type SecureString --region $REGION

  aws ssm put-parameter --name $PM_ROTATION_TEST_NAME --value BeforeRotation --type SecureString --region $REGION
  aws secretsmanager create-secret --name $SM_ROT_TEST_NAME --secret-string BeforeRotation --region $REGION

  sleep 30

  run kubectl create ns $NAMESPACE
  assert_success 

  run kubectl label ns $NAMESPACE security.openshift.io/scc.podSecurityLabelSync=false pod-security.kubernetes.io/enforce=privileged pod-security.kubernetes.io/audit=privileged pod-security.kubernetes.io/warn=privileged --overwrite
  assert_success

  cat > $BATS_TEST_DIR/csi-app-assume-role-policy-document.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${ACCOUNT_NUMBER}:oidc-provider/${OIDC_PROVIDER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER}:sub": "system:serviceaccount:${NAMESPACE}:basic-test-mount-sa"
        }
      }
    }
  ]
}
EOF

  ROLE=$(aws iam create-role \
    --role-name "${CSI_APP_ROLE_NAME}" \
    --assume-role-policy-document file://$BATS_TEST_DIR/csi-app-assume-role-policy-document.json \
    --query "Role.Arn" --output text)

  cat > $BATS_TEST_DIR/csi-app-secret-iam-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret",        
        "ssm:GetParameter",
        "ssm:GetParameters"
      ],
      "Resource": [
        "arn:*:secretsmanager:*:*:secret:$SM_TEST_1_NAME-??????",
        "arn:*:secretsmanager:*:*:secret:$SM_TEST_2_NAME-??????",
        "arn:*:secretsmanager:*:*:secret:$SM_SYNC_NAME-??????",
        "arn:*:secretsmanager:*:*:secret:$SM_ROT_TEST_NAME-??????",
        "arn:*:ssm:*:*:parameter/$PM_TEST_1_NAME*",
        "arn:*:ssm:*:*:parameter/$PM_TEST_LONG_NAME*",
        "arn:*:ssm:*:*:parameter/$PM_ROTATION_TEST_NAME*"
      ]
    }
  ]
}
EOF

  POLICY=$(aws iam create-policy --policy-name "${CSI_APP_POLICY_NAME}" \
    --policy-document file://$BATS_TEST_DIR/csi-app-secret-iam-policy.json \
    --query 'Policy.Arn' --output text)

  aws iam attach-role-policy \
    --role-name "${CSI_APP_ROLE_NAME}" \
    --policy-arn $POLICY --output text

  run kubectl create sa basic-test-mount-sa -n $NAMESPACE
  assert_success 

  run kubectl annotate -n $NAMESPACE sa/basic-test-mount-sa eks.amazonaws.com/role-arn="$ROLE"
  assert_success 
}

teardown_file() {
    aws secretsmanager delete-secret --secret-id $SM_TEST_1_NAME --force-delete-without-recovery --region $REGION
    aws secretsmanager delete-secret --secret-id $SM_TEST_2_NAME --force-delete-without-recovery --region $REGION
    aws secretsmanager delete-secret --secret-id $SM_SYNC_NAME --force-delete-without-recovery --region $REGION

    aws ssm delete-parameter --name $PM_TEST_1_NAME --region $REGION
    aws ssm delete-parameter --name $PM_TEST_LONG_NAME --region $REGION 

    aws ssm delete-parameter --name $PM_ROTATION_TEST_NAME --region $REGION
    aws secretsmanager delete-secret --secret-id $SM_ROT_TEST_NAME --force-delete-without-recovery --region $REGION

    aws iam detach-role-policy --role-name "${CSI_APP_ROLE_NAME}" --policy-arn "$POLICY"
    aws iam delete-policy --policy-arn "$POLICY"
    aws iam delete-role --role-name "${CSI_APP_ROLE_NAME}"

    aws iam detach-user-policy --user-name $AWS_USER_NAME --policy-arn $PAS_POLICY
    aws iam delete-policy --policy-arn $PAS_POLICY
}

@test "Install aws provider" {
  # install the aws provider using the helm charts
  helm repo add aws-secrets-manager https://aws.github.io/secrets-store-csi-driver-provider-aws
  helm repo update
  helm install csi aws-secrets-manager/secrets-store-csi-driver-provider-aws \
    -n $CSI_DRIVER_INSTALLED_NAMESPACE \
    --set "logVerbosity=5" \
    --set-json tolerations='[{"operator":"Exists"}]' \
    --set-json securityContext='{"privileged":true,"allowPrivilegeEscalation":null}'

  sleep 30
  kubectl get ds -n $CSI_DRIVER_INSTALLED_NAMESPACE
  oc adm policy add-scc-to-user privileged -z csi-secrets-store-provider-aws -n $CSI_DRIVER_INSTALLED_NAMESPACE

  # wait for aws-csi-provider pod to be running
  kubectl --namespace $CSI_DRIVER_INSTALLED_NAMESPACE wait --for=condition=Ready --timeout=150s pod -l app=secrets-store-csi-driver-provider-aws

  PROVIDER_POD=$(kubectl --namespace $CSI_DRIVER_INSTALLED_NAMESPACE get pod -l app=secrets-store-csi-driver-provider-aws -o jsonpath="{.items[0].metadata.name}")	
  run kubectl --namespace $CSI_DRIVER_INSTALLED_NAMESPACE get pod/$PROVIDER_POD
  assert_success
}

@test "deploy aws secretproviderclass crd" {
   envsubst < $BATS_TEST_DIR/BasicTestMountSPC.yaml | kubectl --namespace $NAMESPACE apply -f -

   cmd="kubectl --namespace $NAMESPACE get secretproviderclasses.secrets-store.csi.x-k8s.io/basic-test-mount-spc -o yaml | grep aws"
   wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"
}

@test "CSI inline volume test with pod portability" {
   kubectl --namespace $NAMESPACE apply -f $BATS_TEST_DIR/BasicTestMount.yaml
   kubectl --namespace $NAMESPACE  wait --for=condition=Ready --timeout=60s pod/basic-test-mount

   run kubectl --namespace $NAMESPACE  get pod/$POD_NAME
   assert_success
}

@test "CSI inline volume test with rotation - parameter store" {
   result=$(kubectl --namespace $NAMESPACE exec $POD_NAME -- cat /mnt/secrets-store/$PM_ROTATION_TEST_NAME)
   [[ "${result//$'\r'}" == "BeforeRotation" ]]

   aws ssm put-parameter --name $PM_ROTATION_TEST_NAME --value AfterRotation --type SecureString --overwrite --region $REGION
   sleep 120
   result=$(kubectl --namespace $NAMESPACE exec $POD_NAME -- cat /mnt/secrets-store/$PM_ROTATION_TEST_NAME)
   [[ "${result//$'\r'}" == "AfterRotation" ]]
}

@test "CSI inline volume test with rotation - secrets manager" {
   result=$(kubectl --namespace $NAMESPACE exec $POD_NAME -- cat /mnt/secrets-store/$SM_ROT_TEST_NAME)
   [[ "${result//$'\r'}" == "BeforeRotation" ]]
  
   aws secretsmanager put-secret-value --secret-id $SM_ROT_TEST_NAME --secret-string AfterRotation --region $REGION
   sleep 120
   result=$(kubectl --namespace $NAMESPACE exec $POD_NAME -- cat /mnt/secrets-store/$SM_ROT_TEST_NAME)
   [[ "${result//$'\r'}" == "AfterRotation" ]]
}

@test "CSI inline volume test with pod portability - read ssm parameters from pod" {
   result=$(kubectl --namespace $NAMESPACE exec $POD_NAME -- cat /mnt/secrets-store/$PM_TEST_1_NAME)
   [[ "${result//$'\r'}" == "ParameterStoreTest1Value" ]]

   result=$(kubectl --namespace $NAMESPACE exec $POD_NAME -- cat /mnt/secrets-store/ParameterStoreTest2)
   [[ "${result//$'\r'}" == "ParameterStoreTest2Value" ]]
}

@test "CSI inline volume test with pod portability - read secrets manager secrets from pod" {
   result=$(kubectl --namespace $NAMESPACE exec $POD_NAME -- cat /mnt/secrets-store/$SM_TEST_1_NAME)
   [[ "${result//$'\r'}" == "SecretsManagerTest1Value" ]]
   
   result=$(kubectl --namespace $NAMESPACE exec $POD_NAME -- cat /mnt/secrets-store/SecretsManagerTest2)
   [[ "${result//$'\r'}" == "SecretsManagerTest2Value" ]]        
}

@test "Sync with Kubernetes Secret" { 
   run kubectl get secret --namespace $NAMESPACE secret
   assert_success

   result=$(kubectl --namespace=$NAMESPACE get secret secret -o jsonpath="{.data.username}" | base64 -d)
   [[ "$result" == "SecretUser" ]]
}

@test "CSI inline volume test with pod portability - unmount succeeds" {
  # On Linux a failure to unmount the tmpfs will block the pod from being
  # deleted.
  run kubectl --namespace $NAMESPACE delete -f $BATS_TEST_DIR/BasicTestMount.yaml
  assert_success

  run kubectl wait --for=delete --timeout=${WAIT_TIME}s --namespace $NAMESPACE pod/$POD_NAME
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

  run wait_for_process $WAIT_TIME $SLEEP_TIME "check_secret_deleted secret $NAMESPACE"
  assert_success
}

# teardown_file() {
#   archive_info || true
# }
