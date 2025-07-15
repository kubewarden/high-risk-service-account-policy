use lazy_static::lazy_static;

use guest::prelude::*;
use kubewarden_policy_sdk::wapc_guest as guest;

use k8s_openapi::api::core::v1 as apicore;

extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{
    host_capabilities::kubernetes::{CanIRequest, ResourceAttributes, SubjectAccessReview, can_i},
    logging, protocol_version_guest,
    request::ValidationRequest,
    validate_settings,
};

mod settings;
use settings::{Rule, Settings};

use slog::{Logger, debug, info, o, warn};

lazy_static! {
    static ref LOG_DRAIN: Logger = Logger::root(
        logging::KubewardenDrain::new(),
        o!("policy" => "high-risk-service-account-policy")
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn build_sar_vec_from_rule(service_account: &str, rule: &Rule) -> Vec<SubjectAccessReview> {
    Vec::<ResourceAttributes>::from(rule)
        .iter()
        .map(|resource_attribute| SubjectAccessReview {
            user: service_account.to_owned(),
            resource_attributes: resource_attribute.clone(),
            ..Default::default()
        })
        .collect()
}

fn build_subject_access_reviews(service_account: &str, rules: &[Rule]) -> Vec<SubjectAccessReview> {
    rules
        .iter()
        .flat_map(|rule| build_sar_vec_from_rule(service_account, rule))
        .collect()
}

/// Validates a PodSpec against the configured block rules.
/// Raises an error if the PodSpec uses a service account that has high-risk permissions
fn validate_pod(
    pod_spec: apicore::PodSpec,
    namespace: &str,
    settings: &Settings,
) -> Result<(), String> {
    if pod_spec.automount_service_account_token == Some(false) {
        debug!(
            LOG_DRAIN,
            "Pod does not require service account token, skipping validation."
        );
        return Ok(());
    }

    let service_account = pod_spec
        .service_account_name
        .map(|sa| format!("system:serviceaccount:{namespace}:{sa}"))
        .unwrap_or_else(|| format!("system:serviceaccount:{namespace}:default"));

    info!(
        LOG_DRAIN,
        "Validating pod with service account: {}", service_account
    );

    let subject_access_reviews =
        build_subject_access_reviews(&service_account, settings.block_rules.as_slice());
    let mut can_i_failure_counter = 0;

    for sar in &subject_access_reviews {
        let can_i_request = CanIRequest {
            subject_access_review: sar.to_owned(),
            disable_cache: false,
        };

        match can_i(can_i_request) {
            Ok(status) if status.allowed => {
                // exit immediately whe allowed to do a high risk operation,
                // this is a performance optimization
                return Err(build_rejection_message(
                    &service_account,
                    &sar.resource_attributes,
                ));
            }
            Ok(_) => {
                // nothing to do, not allowed to do high risk operations
            }
            Err(e) => {
                warn!(LOG_DRAIN, "Failed to check permissions: {}", e);
                can_i_failure_counter += 1;
                continue;
            }
        }
    }

    if can_i_failure_counter == subject_access_reviews.len() {
        // none of the SubjectAccessReviews were successful, we prefer to be cautious
        // and reject the request
        return Err("Failed to check permissions for all SubjectAccessReviews".to_owned());
    }

    Ok(())
}

fn build_rejection_message(
    service_account: &str,
    resource_attributes: &ResourceAttributes,
) -> String {
    let resource_operation = if let Some(namespace) = &resource_attributes.namespace {
        format!(
            "{} {}/{} in namespace '{}'",
            resource_attributes.verb,
            resource_attributes.group.clone().unwrap_or_default(),
            resource_attributes.resource,
            namespace,
        )
    } else {
        format!(
            "{} {}/{} in the cluster",
            resource_attributes.verb,
            resource_attributes.group.clone().unwrap_or_default(),
            resource_attributes.resource
        )
    };

    format!(
        "Cannot use service account '{service_account}' with permissions to perform {resource_operation}",
    )
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;
    match validation_request.extract_pod_spec_from_object() {
        Ok(pod_spec) => {
            if let Err(error) = validate_pod(
                pod_spec.unwrap_or_default(),
                &validation_request.request.namespace,
                &validation_request.settings,
            ) {
                return kubewarden::reject_request(Some(error), Some(403), None, None);
            }
        }
        Err(e) => {
            warn!(LOG_DRAIN, "Failed to extract pod spec: {}", e);
            return kubewarden::reject_request(
                Some("Failed to extract pod spec".to_owned()),
                Some(400),
                None,
                None,
            );
        }
    }
    kubewarden::accept_request()
}

#[cfg(test)]
mod tests {

    use crate::settings::Verbs;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case(Some("test".to_string()))]
    #[case(None)]
    fn test_rejection_message(#[case] namespace: Option<String>) {
        let service_account = "test-sa";
        let resource_attributes = ResourceAttributes {
            namespace: namespace.clone(),
            verb: "create".to_owned(),
            group: Some("test-group".to_owned()),
            resource: "test-resource".to_owned(),
            ..Default::default()
        };
        let expected_base_msg = "Cannot use service account 'test-sa' with permissions to perform create test-group/test-resource";
        let expected_msg = if let Some(namespace) = namespace {
            format!("{expected_base_msg} in namespace '{namespace}'")
        } else {
            format!("{expected_base_msg} in the cluster")
        };

        let message = build_rejection_message(service_account, &resource_attributes);
        assert_eq!(message, expected_msg);
    }

    #[test]
    fn validate_sar_build() {
        let rules = vec![
            Rule {
                namespace: None,
                api_groups: vec!["group1".to_owned(), "group2".to_owned()],
                resources: vec!["myresource".to_owned(), "otherresource".to_owned()],
                verbs: vec![Verbs::Create, Verbs::Update],
            },
            Rule {
                namespace: Some("mynamespace".to_owned()),
                api_groups: vec!["group1".to_owned(), "group2".to_owned()],
                resources: vec!["myresource".to_owned(), "otherresource".to_owned()],
                verbs: vec![Verbs::Create, Verbs::Update],
            },
        ];

        let sar = build_subject_access_reviews("test-sa", &rules);
        assert_eq!(
            sar,
            vec![
                SubjectAccessReview {
                    user: "test-sa".to_owned(),
                    resource_attributes: ResourceAttributes {
                        namespace: None,
                        verb: "create".to_owned(),
                        group: Some("group1".to_owned()),
                        resource: "myresource".to_owned(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    user: "test-sa".to_owned(),
                    resource_attributes: ResourceAttributes {
                        namespace: None,
                        verb: "update".to_owned(),
                        group: Some("group1".to_owned()),
                        resource: "myresource".to_owned(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    user: "test-sa".to_owned(),
                    resource_attributes: ResourceAttributes {
                        namespace: None,
                        verb: "create".to_owned(),
                        group: Some("group1".to_owned()),
                        resource: "otherresource".to_owned(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    user: "test-sa".to_owned(),
                    resource_attributes: ResourceAttributes {
                        namespace: None,
                        verb: "update".to_owned(),
                        group: Some("group1".to_owned()),
                        resource: "otherresource".to_owned(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    user: "test-sa".to_owned(),
                    resource_attributes: ResourceAttributes {
                        namespace: None,
                        verb: "create".to_owned(),
                        group: Some("group2".to_owned()),
                        resource: "myresource".to_owned(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    user: "test-sa".to_owned(),
                    resource_attributes: ResourceAttributes {
                        namespace: None,
                        verb: "update".to_owned(),
                        group: Some("group2".to_owned()),
                        resource: "myresource".to_owned(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    user: "test-sa".to_owned(),
                    resource_attributes: ResourceAttributes {
                        namespace: None,
                        verb: "create".to_owned(),
                        group: Some("group2".to_owned()),
                        resource: "otherresource".to_owned(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    user: "test-sa".to_owned(),
                    resource_attributes: ResourceAttributes {
                        namespace: None,
                        verb: "update".to_owned(),
                        group: Some("group2".to_owned()),
                        resource: "otherresource".to_owned(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    user: "test-sa".to_owned(),
                    resource_attributes: ResourceAttributes {
                        namespace: Some("mynamespace".to_owned()),
                        verb: "create".to_owned(),
                        group: Some("group1".to_owned()),
                        resource: "myresource".to_owned(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    user: "test-sa".to_owned(),
                    resource_attributes: ResourceAttributes {
                        namespace: Some("mynamespace".to_owned()),
                        verb: "update".to_owned(),
                        group: Some("group1".to_owned()),
                        resource: "myresource".to_owned(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    user: "test-sa".to_owned(),
                    resource_attributes: ResourceAttributes {
                        namespace: Some("mynamespace".to_owned()),
                        verb: "create".to_owned(),
                        group: Some("group1".to_owned()),
                        resource: "otherresource".to_owned(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    user: "test-sa".to_owned(),
                    resource_attributes: ResourceAttributes {
                        namespace: Some("mynamespace".to_owned()),
                        verb: "update".to_owned(),
                        group: Some("group1".to_owned()),
                        resource: "otherresource".to_owned(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    user: "test-sa".to_owned(),
                    resource_attributes: ResourceAttributes {
                        namespace: Some("mynamespace".to_owned()),
                        verb: "create".to_owned(),
                        group: Some("group2".to_owned()),
                        resource: "myresource".to_owned(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    user: "test-sa".to_owned(),
                    resource_attributes: ResourceAttributes {
                        namespace: Some("mynamespace".to_owned()),
                        verb: "update".to_owned(),
                        group: Some("group2".to_owned()),
                        resource: "myresource".to_owned(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    user: "test-sa".to_owned(),
                    resource_attributes: ResourceAttributes {
                        namespace: Some("mynamespace".to_owned()),
                        verb: "create".to_owned(),
                        group: Some("group2".to_owned()),
                        resource: "otherresource".to_owned(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    user: "test-sa".to_owned(),
                    resource_attributes: ResourceAttributes {
                        namespace: Some("mynamespace".to_owned()),
                        verb: "update".to_owned(),
                        group: Some("group2".to_owned()),
                        resource: "otherresource".to_owned(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ]
        );
    }
}
