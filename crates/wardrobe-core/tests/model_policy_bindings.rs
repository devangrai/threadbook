use serde_json::Value;
use wardrobe_core::{
    OUTFIT_RECOMMENDATION_MODEL_V1, OUTFIT_RECOMMENDATION_PROVIDER_V1, TRY_ON_MODEL_V1,
    TRY_ON_PROVIDER_V1,
};

fn policy() -> Value {
    serde_json::from_str(include_str!("../../../release/supply-chain-policy-v1.json"))
        .expect("release supply-chain policy must be valid JSON")
}

#[test]
fn generated_remote_model_bindings_match_the_reviewed_release_policy() {
    let policy = policy();
    let services = &policy["models"]["remote_services"];

    assert_eq!(
        services["outfit_recommendation"]["provider"],
        OUTFIT_RECOMMENDATION_PROVIDER_V1
    );
    assert_eq!(
        services["outfit_recommendation"]["model"],
        OUTFIT_RECOMMENDATION_MODEL_V1
    );
    assert_eq!(
        services["try_on_visualization"]["provider"],
        TRY_ON_PROVIDER_V1
    );
    assert_eq!(services["try_on_visualization"]["model"], TRY_ON_MODEL_V1);
    assert_eq!(
        policy["models"]["remote_model_code_allowed"],
        Value::Bool(false)
    );
    assert_eq!(
        policy["models"]["local_providers"]["segmentation"]["availability"],
        "unavailable"
    );
}
