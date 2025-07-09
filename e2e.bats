#!/usr/bin/env bats

@test "Accept service account with no risky permissions" {
	run kwctl run  --request-path test_data/pod_creation.json  --allow-context-aware \
		--settings-path test_data/settings.json \
		--replay-host-capabilities-interactions test_data/session_return_false.yml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

	[ "$status" -eq 0 ]
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
	[ $(expr "$output" : '.*Cannot shut down the CallbackHandler task.*') -eq 0 ]
}

@test "Reject service account with risky permissions" {
	run kwctl run  --request-path test_data/pod_creation.json  --allow-context-aware \
		--settings-path test_data/settings.json \
		--replay-host-capabilities-interactions test_data/session_return_true.yml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

	[ "$status" -eq 0 ]
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	[ $(expr "$output" : '.*"Cannot use service account '\''system:serviceaccount:default:my-service-account'\'' with permissions to perform the following actions: create /pods in namespace not-specified.*') -ne 0 ]
	[ $(expr "$output" : '.*create apps/deployments in namespace not-specified.*') -ne 0 ]
	
}

@test "With no service account, should use the default service account" {
	run kwctl run  --request-path test_data/pod_creation_without_service_account.json  \
	--allow-context-aware --settings-path test_data/settings.json \
	--replay-host-capabilities-interactions test_data/session_return_true_default_service_account.yml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

	[ "$status" -eq 0 ]
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	[ $(expr "$output" : '.*"Cannot use service account '\''system:serviceaccount:mynamespace:default'\'' with permissions to perform the following actions: create /pods in namespace not-specified.*') -ne 0 ]
	[ $(expr "$output" : '.*create apps/deployments in namespace not-specified.*') -ne 0 ]
}
