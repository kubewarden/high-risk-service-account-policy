[![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#stable)

# High-Risk Service Account Blocker

Kubernetes [service
accounts](https://kubernetes.io/docs/concepts/security/service-accounts/) are
account types used by workloads running in the cluster. A service account can
grant credentials to workloads, enabling them to perform a wide range of
cluster operations. This can be dangerous when a workload is able to manipulate
resources it is not authorized to. This policy aims to mitigate such risks by
preventing resources that utilize high-risk service accounts from being
deployed in the cluster. To achieve this, the policy inspects the roles
associated with the service account in use. If any of the rules are considered
high-risk, the request is rejected.

Every time a resource that defines a service account is submitted to the
cluster, the policy will fetch its associated roles and cluster roles and check
if their rules are a subset of the rules defined in the policy's configuration.
If they are, the resource is rejected.

## Settings

The policy settings consist of a list of rules that service accounts are
prohibited from having defined in any of their associated roles and cluster
roles. The rules follow the same syntax as those defined in the
[roles](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.32/#policyrule-v1-rbac-authorization-k8s-io)
specification.

```yaml
blockRules:
  # For listing secrets
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["list"]

  # For executing commands in containers
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create"]

  # Full access to all workload resources
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["*"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]
    verbs: ["*"]
  - apiGroups: ["batch"]
    resources: ["jobs", "cronjobs"]
    verbs: ["*"]
  - apiGroups: ["autoscaling"]
    resources: ["horizontalpodautoscalers"]
    verbs: ["*"]

  # Full access to RBAC resources within a namespace
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles", "rolebindings"]
    verbs: ["*"]
    namespace: "mynamespace"
```

For example, if the policy is deployed with the previous configuration in a
cluster that has a service account like this:

```yaml
---
# ServiceAccount
apiVersion: v1
kind: ServiceAccount
metadata:
  name: super-admin-sa
  namespace: default

---
# Powerful Role with all requested permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: super-admin-role
  namespace: default
rules:
  # For listing secrets
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["list"]

  # For executing commands in containers
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create"]

  # Full access to all workload resources
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["*"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]
    verbs: ["*"]
  - apiGroups: ["batch"]
    resources: ["jobs", "cronjobs"]
    verbs: ["*"]
  - apiGroups: ["autoscaling"]
    resources: ["horizontalpodautoscalers"]
    verbs: ["*"]
  # Full access to RBAC resources within namespace
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles", "rolebindings"]
    verbs: ["*"]

---
# RoleBinding for namespace-scoped permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: super-admin-rolebinding
  namespace: default
subjects:
  - kind: ServiceAccount
    name: super-admin-sa
    namespace: default
roleRef:
  kind: Role
  name: super-admin-role
  apiGroup: rbac.authorization.k8s.io
```

The following deployment would not be allowed in the cluster:

```yaml
---
# Deployment using the powerful ServiceAccount
apiVersion: apps/v1
kind: Deployment
metadata:
  name: super-admin-deployment
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: super-admin-app
  template:
    metadata:
      labels:
        app: super-admin-app
    spec:
      serviceAccountName: super-admin-sa
      containers:
        - name: main
          image: nginx:alpine
          ports:
            - containerPort: 80
        - name: kubectl
          image: bitnami/kubectl:latest
          command: ["sleep", "infinity"]
```
