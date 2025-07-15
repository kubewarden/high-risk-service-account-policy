[![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#stable)

# High-Risk Service Account Blocker

Kubernetes [service
accounts](https://kubernetes.io/docs/concepts/security/service-accounts/) are
account types used by workloads running in the cluster. A service account can
grant credentials to workloads, enabling them to perform a wide range of
cluster operations. This can be dangerous when a workload is able to manipulate
resources it is not authorized to. This policy aims to mitigate such risks by
preventing resources that utilize high-risk service accounts from being
deployed in the cluster. To achieve this, the policy leverages the Kubernetes
authorization API. It assesses whether a service account has permissions to
perform operations that are not allowed. If such unauthorized permissions are
detected, the request is rejected.

Every time a resource that uses a service account is submitted to the cluster,
the policy will query the Kubernetes authorization API the to check if the
given ServiceAccount has some permissions that it shouldn't. To perform this
verification, the policy will create an
[SubjectAccessReview](https://kubernetes.io/docs/reference/kubernetes-api/authorization-resources/subject-access-review-v1/)
and apply it to cluster check the service account permissions. If the result
returned that the service account can perform such operation, the request is
rejected.

When the policy builds the `SubjectAccessReview` the user set in in the
resource is defined by `system:serviceaccount:<namespace>:<service-account>`.
Where the `namespace` is the namespace from the request and the
`service-account` is the service account from the resource being deployed or
the `default` one.

The policy rejects a workload as soon as it found a blocked operation.
Therefore, it avoids hitting the Kubernetes API too many times before rejecting
the request.

## Kubernetes Authorization API considerations

Kubernetes authorization API allow cluster operators to define multiple
authorizers (or authorization plugins). Each one can have different results.
And to reflect this the `SubjectAccessReviewStatus` (which is the data returned
when a `SubjectAccessReview` is created) has two fields express all the possibles
results. The fields are `allowed` and `denied`.

The authorization plugins can:

- allow an operation. This means that the `SubjectAccessReviewStatus` returned
  by it will have the `allowed` set to `true` and `denied: false`. Any other authorizaiton plugin
  will be ignored

- deny the operation. This means that the `SubjectAccessReviewStatus` returned
  by it will have `denied: true` and `allowed: false`. This will short-circuit the authorization flow
  and reject the operation. Any other authorizaiton plugin will be ignored

- no decision. In this case the plugin does not have a final decision to allow or
  deny the operation. Therefore, both `allowed` and `denied` fields are set to `false`.
  This give the opportunity to other plugins to evaluate the operation.

In summary, the `denied` field is used to short-circuit the authorization
flow. This means that, if any plugin return it `denied: true`, the
authorization immediately forbid the request. And the `allowed` fields is to allow
an operation right away. However, if the plugin does not allow or deny the request, but it wants to give the
opportunity to other plugins to authorize, it returns `denied: false` or unset
and return `allowed:false`.

These are the possible outcome after all the authorization plugins run:

- `{allowed: true, denied: false}`: some plugin allowed the request. Any remain
  plugins are skipped
- `{allowed: false, denied: true}`: some plugin explicit denied the request.
  Any remain plugins are skipped
- `{allowed: false, denied: false}` : all authorizers abstain a response to the
  request.

> [!IMPORTANT]
>
> - `{allowed: true, denied: true}` : this is not allowed. Both fields are mutual
>   exclusive

This policy **only** cares about the `allowed` field. Because this are the
field that show that the operation under evaluation is permitted. Therefore,
this is the case where the admission request should be rejected. All the
other scenarios, are ignored by the policy and the admission request is
accepted.

## Example

The policy settings consist of a list of rules that service accounts are
prohibited from having defined in any of their associated roles and cluster
roles. The rules follow the same syntax as those defined in the
[roles](https://kubernetes.io/docs/reference/kubernetes-api/authorization-resources/subject-access-review-v1/)
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

The verbs field allow the following values: `create`, `update`, `delete`,
`get`, `list`, `watch`, `proxy`, `*`, `patch` and `deletecollection`.

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

In the prevous example, the user set in the `SubjectAccessReview` resource
would be `syste:serviceaccount:default:super-admin-sa`.
