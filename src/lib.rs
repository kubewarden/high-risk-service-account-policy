use lazy_static::lazy_static;

use guest::prelude::*;
use kubewarden_policy_sdk::wapc_guest as guest;

use k8s_openapi::api::{authorization::v1::SubjectAccessReview, core::v1 as apicore};

extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{
    host_capabilities::kubernetes::{can_i, SubjectAccessReviewRequest},
    logging, protocol_version_guest,
    request::ValidationRequest,
    validate_settings,
};

mod settings;
use settings::{Rule, Settings};

use slog::{info, o, warn, Logger};

lazy_static! {
    static ref LOG_DRAIN: Logger = Logger::root(
        logging::KubewardenDrain::new(),
        o!("policy" => "high-risk-service-account-policy")
    );
}

#[no_mangle]
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
                    spec: k8s_openapi::api::authorization::v1::SubjectAccessReviewSpec {
                        user: Some(service_account.to_owned()),
                        resource_attributes: Some(
                            k8s_openapi::api::authorization::v1::ResourceAttributes {
                                namespace: rule.namespace.clone(),
                                verb: Some(verb.to_owned()),
                                group: Some(api_group.to_owned()),
                                resource: Some(resource.to_owned()),
                                subresource: None,
                                name: None,
                                ..Default::default()
                            },
                        ),
                        non_resource_attributes: None,
                        extra: None,
                        groups: None,
                        uid: None,
                    },
                    ..Default::default()
                })
            })
        })
        .collect()
}

fn build_subject_access_review(
    service_account: String,
    rules: &[Rule],
) -> Vec<SubjectAccessReview> {
    rules
        .iter()
        .flat_map(|rule| build_sar_from_rule(&service_account, rule))
        .collect()
}

fn validate_pod(
    pod_spec: apicore::PodSpec,
    namespace: String,
    settings: &Settings,
) -> Result<(), String> {
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
        build_subject_access_review(service_account.clone(), settings.block_rules.as_slice());

    let statuses = subject_access_reviews
        .iter()
        .filter_map(|sar| {
            let sarr = SubjectAccessReviewRequest {
                subject_access_review: sar.clone(),
                disable_cache: false,
            };
            let status = can_i(sarr);
            match status {
                Ok(status) => {
                    if status.allowed {
                        let resource_attributes =
                            sar.spec.resource_attributes.clone().unwrap_or_default();
                        return Some(format!(
                            "{} {}/{} in namespace {}",
                            resource_attributes
                                .verb
                                .unwrap_or("not-specified".to_owned()),
                            resource_attributes
                                .group
                                .unwrap_or("not-specified".to_owned()),
                            resource_attributes
                                .resource
                                .unwrap_or("not-specified".to_owned()),
                            resource_attributes
                                .namespace
                                .unwrap_or("not-specified".to_owned())
                        ));
                    }
                    None
                }
                Err(e) => {
                    warn!(LOG_DRAIN, "Failed to check permissions: {}", e);
                    Some(format!(
                        "Failed to check permissions for service account '{service_account}': {e}",
                    ))
                }
            }
        })
        .collect::<Vec<String>>();
    if !statuses.is_empty() {
        let error_msg = format!(
            "Cannot use service account '{}' with permissions to perform the following actions: {}",
            service_account,
            statuses.join(", ")
        );
        return Err(error_msg);
    }
    Ok(())
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
                Some(500),
                None,
                None,
            );
        }
    }
    kubewarden::accept_request()
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::authorization::v1::ResourceAttributes;

    use super::*;

    #[test]
    fn validate_sar_build() {
        let rules = vec![
            Rule {
                namespace: None,
                api_groups: vec!["group1".to_owned(), "group2".to_owned()],
                resources: vec!["myresource".to_owned(), "otherresource".to_owned()],
                verbs: vec!["create".to_owned(), "update".to_owned()],
            },
            Rule {
                namespace: Some("mynamespace".to_owned()),
                api_groups: vec!["group1".to_owned(), "group2".to_owned()],
                resources: vec!["myresource".to_owned(), "otherresource".to_owned()],
                verbs: vec!["create".to_owned(), "update".to_owned()],
            },
        ];

        let sar = build_subject_access_review("test-sa".to_owned(), &rules);
        assert_eq!(
            sar,
            vec![
                SubjectAccessReview {
                    spec: k8s_openapi::api::authorization::v1::SubjectAccessReviewSpec {
                        user: Some("test-sa".to_owned()),
                        resource_attributes: Some(ResourceAttributes {
                            namespace: None,
                            verb: Some("create".to_owned()),
                            group: Some("group1".to_owned()),
                            resource: Some("myresource".to_owned()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    spec: k8s_openapi::api::authorization::v1::SubjectAccessReviewSpec {
                        user: Some("test-sa".to_owned()),
                        resource_attributes: Some(ResourceAttributes {
                            namespace: None,
                            verb: Some("update".to_owned()),
                            group: Some("group1".to_owned()),
                            resource: Some("myresource".to_owned()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    spec: k8s_openapi::api::authorization::v1::SubjectAccessReviewSpec {
                        user: Some("test-sa".to_owned()),
                        resource_attributes: Some(ResourceAttributes {
                            namespace: None,
                            verb: Some("create".to_owned()),
                            group: Some("group1".to_owned()),
                            resource: Some("otherresource".to_owned()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    spec: k8s_openapi::api::authorization::v1::SubjectAccessReviewSpec {
                        user: Some("test-sa".to_owned()),
                        resource_attributes: Some(ResourceAttributes {
                            namespace: None,
                            verb: Some("update".to_owned()),
                            group: Some("group1".to_owned()),
                            resource: Some("otherresource".to_owned()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    spec: k8s_openapi::api::authorization::v1::SubjectAccessReviewSpec {
                        user: Some("test-sa".to_owned()),
                        resource_attributes: Some(ResourceAttributes {
                            namespace: None,
                            verb: Some("create".to_owned()),
                            group: Some("group2".to_owned()),
                            resource: Some("myresource".to_owned()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    spec: k8s_openapi::api::authorization::v1::SubjectAccessReviewSpec {
                        user: Some("test-sa".to_owned()),
                        resource_attributes: Some(ResourceAttributes {
                            namespace: None,
                            verb: Some("update".to_owned()),
                            group: Some("group2".to_owned()),
                            resource: Some("myresource".to_owned()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    spec: k8s_openapi::api::authorization::v1::SubjectAccessReviewSpec {
                        user: Some("test-sa".to_owned()),
                        resource_attributes: Some(ResourceAttributes {
                            namespace: None,
                            verb: Some("create".to_owned()),
                            group: Some("group2".to_owned()),
                            resource: Some("otherresource".to_owned()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    spec: k8s_openapi::api::authorization::v1::SubjectAccessReviewSpec {
                        user: Some("test-sa".to_owned()),
                        resource_attributes: Some(ResourceAttributes {
                            namespace: None,
                            verb: Some("update".to_owned()),
                            group: Some("group2".to_owned()),
                            resource: Some("otherresource".to_owned()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    spec: k8s_openapi::api::authorization::v1::SubjectAccessReviewSpec {
                        user: Some("test-sa".to_owned()),
                        resource_attributes: Some(ResourceAttributes {
                            namespace: Some("mynamespace".to_owned()),
                            verb: Some("create".to_owned()),
                            group: Some("group1".to_owned()),
                            resource: Some("myresource".to_owned()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    spec: k8s_openapi::api::authorization::v1::SubjectAccessReviewSpec {
                        user: Some("test-sa".to_owned()),
                        resource_attributes: Some(ResourceAttributes {
                            namespace: Some("mynamespace".to_owned()),
                            verb: Some("update".to_owned()),
                            group: Some("group1".to_owned()),
                            resource: Some("myresource".to_owned()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    spec: k8s_openapi::api::authorization::v1::SubjectAccessReviewSpec {
                        user: Some("test-sa".to_owned()),
                        resource_attributes: Some(ResourceAttributes {
                            namespace: Some("mynamespace".to_owned()),
                            verb: Some("create".to_owned()),
                            group: Some("group1".to_owned()),
                            resource: Some("otherresource".to_owned()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    spec: k8s_openapi::api::authorization::v1::SubjectAccessReviewSpec {
                        user: Some("test-sa".to_owned()),
                        resource_attributes: Some(ResourceAttributes {
                            namespace: Some("mynamespace".to_owned()),
                            verb: Some("update".to_owned()),
                            group: Some("group1".to_owned()),
                            resource: Some("otherresource".to_owned()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    spec: k8s_openapi::api::authorization::v1::SubjectAccessReviewSpec {
                        user: Some("test-sa".to_owned()),
                        resource_attributes: Some(ResourceAttributes {
                            namespace: Some("mynamespace".to_owned()),
                            verb: Some("create".to_owned()),
                            group: Some("group2".to_owned()),
                            resource: Some("myresource".to_owned()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    spec: k8s_openapi::api::authorization::v1::SubjectAccessReviewSpec {
                        user: Some("test-sa".to_owned()),
                        resource_attributes: Some(ResourceAttributes {
                            namespace: Some("mynamespace".to_owned()),
                            verb: Some("update".to_owned()),
                            group: Some("group2".to_owned()),
                            resource: Some("myresource".to_owned()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    spec: k8s_openapi::api::authorization::v1::SubjectAccessReviewSpec {
                        user: Some("test-sa".to_owned()),
                        resource_attributes: Some(ResourceAttributes {
                            namespace: Some("mynamespace".to_owned()),
                            verb: Some("create".to_owned()),
                            group: Some("group2".to_owned()),
                            resource: Some("otherresource".to_owned()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SubjectAccessReview {
                    spec: k8s_openapi::api::authorization::v1::SubjectAccessReviewSpec {
                        user: Some("test-sa".to_owned()),
                        resource_attributes: Some(ResourceAttributes {
                            namespace: Some("mynamespace".to_owned()),
                            verb: Some("update".to_owned()),
                            group: Some("group2".to_owned()),
                            resource: Some("otherresource".to_owned()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ]
        );
    }
}
