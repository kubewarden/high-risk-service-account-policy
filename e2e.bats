#!/usr/bin/env bats

@test "Accept service account with no risky permissions" {
	run kwctl run  --request-path test_data/pod_creation.json  --allow-context-aware \
		--settings-path test_data/settings.json \
		--replay-host-capabilities-interactions test_data/can_i_returns_not_allowed.yml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

	[ "$status" -eq 0 ]
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
	[ $(expr "$output" : '.*Cannot shut down the CallbackHandler task.*') -eq 0 ]
}

@test "Reject service account with risky permissions" {
	run kwctl run  --request-path test_data/pod_creation.json  --allow-context-aware \
		--settings-path test_data/settings.json \
		--replay-host-capabilities-interactions test_data/can_i_returns_allowed.yml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

	[ "$status" -eq 0 ]
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	[ $(expr "$output" : '.*"Cannot use service account '\''system:serviceaccount:default:my-service-account'\'' with permissions to perform create /pods in the cluster.*') -ne 0 ]
}

@test "With no service account, should use the default service account" {
	run kwctl run  --request-path test_data/pod_creation_without_service_account.json  \
	--allow-context-aware --settings-path test_data/settings.json \
	--replay-host-capabilities-interactions test_data/can_i_default_service_account_returns_allowed.yml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

	[ "$status" -eq 0 ]
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	[ $(expr "$output" : '.*"Cannot use service account '\''system:serviceaccount:mynamespace:default'\'' with permissions to perform create /pods in the cluster.*') -ne 0 ]
}

@test "Accept workloads with no service account mounted" {
	run kwctl run  --request-path test_data/pod_creation_without_service_account_mounted.json  --allow-context-aware \
		--settings-path test_data/settings.json  annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

	[ "$status" -eq 0 ]
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
	[ $(expr "$output" : '.*Cannot shut down the CallbackHandler task.*') -eq 0 ]
}
