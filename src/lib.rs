use lazy_static::lazy_static;

use guest::prelude::*;
use kubewarden_policy_sdk::wapc_guest as guest;

use k8s_openapi::api::{authorization::v1::SubjectAccessReviewStatus, core::v1 as apicore};

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

fn build_sar_from_rule(service_account: &String, rule: &Rule) -> Vec<SubjectAccessReview> {
    rule.api_groups
        .iter()
        .flat_map(|api_group| {
            rule.resources.iter().flat_map(move |resource| {
                rule.verbs.iter().map(move |verb| SubjectAccessReview {
                    user: service_account.to_owned(),
                    resource_attributes: ResourceAttributes {
                        namespace: rule.namespace.clone(),
                        verb: verb.to_string(),
                        group: Some(api_group.to_owned()),
                        resource: resource.to_owned(),
                        subresource: None,
                        name: None,
                        ..Default::default()
                    },
                    ..Default::default()
                })
            })
        })
        .collect()
}

fn build_subject_access_reviews(
    service_account: String,
    rules: &[Rule],
) -> Vec<SubjectAccessReview> {
    rules
        .iter()
        .flat_map(|rule| build_sar_from_rule(&service_account, rule))
        .collect()
}

fn validate_status_response(status: &SubjectAccessReviewStatus) -> Result<(), String> {
    // We do not care about denied resources, we just want to block allowed
    // operations. Furthermore, Kubernetes denies operations by default when
    // authorization plugins abstains to make a decision.
    if status.allowed {
        return Err(status.reason.clone().unwrap_or("".to_owned()));
    }
    if status.evaluation_error.is_some() {
        warn!(
            LOG_DRAIN,
            "Evaluation error for resource: {}",
            status.evaluation_error.as_ref().unwrap()
        );
    }
    Ok(())
}

fn validate_pod(
    pod_spec: apicore::PodSpec,
    namespace: String,
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
        .or(pod_spec.service_account)
        .map(|sa| format!("system:serviceaccount:{namespace}:{sa}"))
        .unwrap_or_else(|| format!("system:serviceaccount:{namespace}:default"));

    info!(
        LOG_DRAIN,
        "Validating pod with service account: {}", service_account
    );

    let subject_access_reviews =
        build_subject_access_reviews(service_account.clone(), settings.block_rules.as_slice());

    for sar in &subject_access_reviews {
        let status = can_i(CanIRequest {
            subject_access_review: sar.clone(),
            disable_cache: false,
        });
        if let Err(e) = status {
            warn!(LOG_DRAIN, "Failed to check permissions: {}", e);
            continue;
        }

        let validation_result = validate_status_response(&status.unwrap())
            .map_err(|e| build_rejection_message(&service_account, &sar.resource_attributes, &e));
        validation_result?
    }
    Ok(())
}

fn build_rejection_message(
    service_account: &str,
    resource_attributes: &ResourceAttributes,
    reason: &str,
) -> String {
    let resource_operation = format!(
        "{} {}/{} in namespace '{}'",
        resource_attributes.verb,
        resource_attributes.group.clone().unwrap_or("".to_owned()),
        resource_attributes.resource,
        resource_attributes
            .namespace
            .clone()
            .unwrap_or("".to_owned()),
    );
    let reason_message = if reason.is_empty() {
        String::new()
    } else {
        format!(": {reason}")
    };

    format!(
        "Cannot use service account '{service_account}' with permissions to perform {resource_operation}{reason_message}",
    )
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;
    match validation_request.extract_pod_spec_from_object() {
        Ok(pod_spec) => {
            if let Err(error) = validate_pod(
                pod_spec.unwrap_or_default(),
                validation_request.request.namespace.to_owned(),
                &validation_request.settings,
            ) {
                return kubewarden::reject_request(Some(error), Some(400), None, None);
            }
        }
        Err(e) => {
            warn!(LOG_DRAIN, "Failed to extract pod spec: {}", e);
            return kubewarden::reject_request(
                Some("Failed to parse request".to_owned()),
                Some(403),
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
    #[case("Insufficient permissions")]
    #[case("")]
    fn test_rejection_message(#[case] reason: &str) {
        let service_account = "test-sa";
        let resource_attributes = ResourceAttributes {
            namespace: Some("test-namespace".to_owned()),
            verb: "create".to_owned(),
            group: Some("test-group".to_owned()),
            resource: "test-resource".to_owned(),
            ..Default::default()
        };
        let mut expected_message = "Cannot use service account 'test-sa' with permissions to perform create test-group/test-resource in namespace 'test-namespace'".to_string();
        if !reason.is_empty() {
            expected_message = format!("{expected_message}: {reason}")
        }

        let message = build_rejection_message(service_account, &resource_attributes, reason);
        assert_eq!(message, expected_message);
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

        let sar = build_subject_access_reviews("test-sa".to_owned(), &rules);
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
