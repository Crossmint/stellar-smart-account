#![cfg(test)]

use soroban_sdk::{map, testutils::BytesN as _, vec, BytesN, IntoVal};

use crate::{
    auth::{
        permissions::SignerRole,
        proof::{SignatureProofs, SignerProof},
        signer::SignerKey,
    },
    error::Error,
    interface::SmartWalletInterface,
    tests::test_utils::{get_token_auth_context, setup, Ed25519TestSigner, TestSignerTrait as _},
    wallet::SmartWallet,
};

extern crate std;

#[test]
fn test_revoke_admin_signer_prevented() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard_signer = Ed25519TestSigner::generate(SignerRole::Standard);
    
    let contract_id = env.register(
        SmartWallet,
        (vec![
            &env,
            admin_signer.into_signer(&env),
            standard_signer.into_signer(&env)
        ],),
    );
    
    let payload = BytesN::random(&env);
    let (signer_key, proof) = admin_signer.sign(&env, &payload);
    let auth_payloads = SignatureProofs(map![&env, (signer_key.clone(), proof.clone())]);
    
    let admin_signer_key = SignerKey::Ed25519(admin_signer.public_key(&env));
    
    env.mock_all_auths();
    let result = env.as_contract(&contract_id, || {
        SmartWallet::revoke_signer(&env, admin_signer_key)
    });
    
    assert_eq!(result.unwrap_err(), Error::CannotRevokeAdminSigner);
}

#[test]
fn test_revoke_standard_signer_allowed() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard_signer = Ed25519TestSigner::generate(SignerRole::Standard);
    
    let contract_id = env.register(
        SmartWallet,
        (vec![
            &env,
            admin_signer.into_signer(&env),
            standard_signer.into_signer(&env)
        ],),
    );
    
    let payload = BytesN::random(&env);
    let (signer_key, proof) = admin_signer.sign(&env, &payload);
    let auth_payloads = SignatureProofs(map![&env, (signer_key.clone(), proof.clone())]);
    
    let standard_signer_key = SignerKey::Ed25519(standard_signer.public_key(&env));
    
    env.mock_all_auths();
    let result = env.as_contract(&contract_id, || {
        SmartWallet::revoke_signer(&env, standard_signer_key)
    });
    
    assert!(result.is_ok());
}
