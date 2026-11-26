use sha2::{Digest, Sha256};
use soroban_sdk::{
    map, testutils::BytesN as _, vec, Address, Bytes, BytesN, Env, IntoVal, Map, Vec,
};

use crate::{
    account::SmartAccount,
    auth::proof::{SignatureProofs, SignerProof},
    auth::signers::SignatureVerifier,
    error::Error,
    tests::test_utils::{
        get_token_auth_context, setup, Ed25519TestSigner, MlDsa65TestSigner, TestSignerTrait,
    },
};
use smart_account_interfaces::{
    Ed25519Signer, MlDsa65Signer, MultisigMember, MultisigSigner, Signer, SignerKey, SignerRole,
};

fn payload_hash(env: &Env) -> soroban_sdk::crypto::Hash<32> {
    env.crypto().sha256(&Bytes::from_array(env, &[0xAB; 32]))
}

fn check_auth(
    env: &Env,
    contract_id: &Address,
    payload: &BytesN<32>,
    proofs: SignatureProofs,
) -> Result<(), Error> {
    env.try_invoke_contract_check_auth::<Error>(
        contract_id,
        payload,
        proofs.into_val(env),
        &vec![env, get_token_auth_context(env)],
    )
    .map(|_| ())
    .map_err(|e| match e {
        Ok(err) => err,
        Err(e) => panic!("{:?}", e),
    })
}

// ============================================================================
// Verifier
// ============================================================================

#[test]
fn test_ml_dsa65_valid_signature() {
    let env = setup();
    let signer = MlDsa65TestSigner::generate(SignerRole::Admin);
    let payload = payload_hash(&env);
    let (_, proof) = signer.sign(&env, &payload.to_bytes());

    MlDsa65Signer::new(signer.public_key(&env))
        .verify(&env, &payload, &proof)
        .unwrap();
}

#[test]
#[should_panic(expected = "Error(Crypto, InvalidInput)")]
fn test_ml_dsa65_signature_from_other_key_panics() {
    let env = setup();
    let signer = MlDsa65TestSigner::generate(SignerRole::Admin);
    let other = MlDsa65TestSigner::generate(SignerRole::Admin);
    let payload = payload_hash(&env);
    let (_, proof) = other.sign(&env, &payload.to_bytes());

    let _ = MlDsa65Signer::new(signer.public_key(&env)).verify(&env, &payload, &proof);
}

#[test]
#[should_panic(expected = "Error(Crypto, InvalidInput)")]
fn test_ml_dsa65_tampered_signature_panics() {
    let env = setup();
    let signer = MlDsa65TestSigner::generate(SignerRole::Admin);
    let payload = payload_hash(&env);
    let (_, proof) = signer.sign(&env, &payload.to_bytes());
    let SignerProof::MlDsa65(signature) = proof else {
        unreachable!()
    };
    let mut bytes = signature.to_array();
    bytes[0] ^= 0x01;
    let tampered = SignerProof::MlDsa65(BytesN::from_array(&env, &bytes));

    let _ = MlDsa65Signer::new(signer.public_key(&env)).verify(&env, &payload, &tampered);
}

#[test]
fn test_ml_dsa65_wrong_proof_type_rejected() {
    let env = setup();
    let ml_dsa = MlDsa65TestSigner::generate(SignerRole::Admin);
    let ed25519 = Ed25519TestSigner::generate(SignerRole::Admin);
    let payload = payload_hash(&env);

    let cases: [(Signer, SignerProof); 2] = [
        (
            ml_dsa.into_signer(&env),
            SignerProof::Ed25519(BytesN::random(&env)),
        ),
        (
            ed25519.into_signer(&env),
            SignerProof::MlDsa65(BytesN::random(&env)),
        ),
    ];
    for (signer, proof) in cases {
        let result = signer.verify(&env, &payload, &proof);
        assert_eq!(result, Err(Error::InvalidProofType));
    }
}

#[test]
fn test_ml_dsa65_signer_key_is_sha256_of_public_key() {
    let env = setup();
    let public_key = MlDsa65TestSigner::generate(SignerRole::Admin).public_key(&env);
    let expected: [u8; 32] = Sha256::digest(public_key.to_array()).into();

    let key: SignerKey = MlDsa65Signer::new(public_key).into();

    assert_eq!(key, SignerKey::MlDsa65(BytesN::from_array(&env, &expected)));
}

// ============================================================================
// __check_auth
// ============================================================================

#[test]
fn test_ml_dsa65_end_to_end_auth() {
    let env = setup();
    let signer = MlDsa65TestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, signer.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );
    let payload = BytesN::random(&env);
    let (key, proof) = signer.sign(&env, &payload);

    check_auth(
        &env,
        &contract_id,
        &payload,
        SignatureProofs(map![&env, (key, proof)]),
    )
    .unwrap();
}

#[test]
fn test_ml_dsa65_unknown_key_id_rejected() {
    let env = setup();
    let signer = MlDsa65TestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, signer.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );
    let payload = BytesN::random(&env);
    let (_, proof) = signer.sign(&env, &payload);
    let unknown_key = SignerKey::MlDsa65(BytesN::random(&env));

    let result = check_auth(
        &env,
        &contract_id,
        &payload,
        SignatureProofs(map![&env, (unknown_key, proof)]),
    );

    assert_eq!(result, Err(Error::SignerNotFound));
}

// ============================================================================
// Hybrid multisig (Ed25519 + ML-DSA-65)
// ============================================================================

struct HybridAccount {
    contract_id: Address,
    multisig_key: SignerKey,
    classic: Ed25519TestSigner,
    post_quantum: MlDsa65TestSigner,
}

fn register_hybrid_account(env: &Env) -> HybridAccount {
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let classic = Ed25519TestSigner::generate(SignerRole::Admin);
    let post_quantum = MlDsa65TestSigner::generate(SignerRole::Admin);
    let id = BytesN::random(env);
    let members = vec![
        env,
        MultisigMember::Ed25519(Ed25519Signer::new(classic.public_key(env))),
        MultisigMember::MlDsa65(MlDsa65Signer::new(post_quantum.public_key(env))),
    ];
    let multisig = Signer::Multisig(
        MultisigSigner::new(id.clone(), members, 2),
        SignerRole::Admin,
    );
    let contract_id = env.register(
        SmartAccount,
        (
            vec![env, admin.into_signer(env), multisig],
            Vec::<Address>::new(env),
        ),
    );
    HybridAccount {
        contract_id,
        multisig_key: SignerKey::Multisig(id),
        classic,
        post_quantum,
    }
}

#[derive(Clone, Copy, Debug)]
enum Member {
    Classic,
    PostQuantum,
}

fn hybrid_auth(env: &Env, account: &HybridAccount, signing: &[Member]) -> Result<(), Error> {
    let payload = BytesN::random(env);
    let mut member_proofs = Map::new(env);
    for member in signing {
        let (key, proof) = match member {
            Member::Classic => account.classic.sign(env, &payload),
            Member::PostQuantum => account.post_quantum.sign(env, &payload),
        };
        member_proofs.set(key, proof);
    }
    let proofs = SignatureProofs(map![
        env,
        (
            account.multisig_key.clone(),
            SignerProof::Multisig(member_proofs)
        )
    ]);
    check_auth(env, &account.contract_id, &payload, proofs)
}

#[test]
fn test_hybrid_multisig_both_members_sign_authorizes() {
    let env = setup();
    let account = register_hybrid_account(&env);

    hybrid_auth(&env, &account, &[Member::Classic, Member::PostQuantum]).unwrap();
}

#[test]
fn test_hybrid_multisig_one_member_sign_rejected() {
    let env = setup();
    let account = register_hybrid_account(&env);

    for member in [Member::Classic, Member::PostQuantum] {
        let result = hybrid_auth(&env, &account, &[member]);
        assert_eq!(result, Err(Error::MultisigThresholdNotMet), "{member:?}");
    }
}

#[test]
#[should_panic(expected = "Error(Contract, #49)")]
fn test_multisig_duplicate_ml_dsa65_member_rejected() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let member =
        MlDsa65Signer::new(MlDsa65TestSigner::generate(SignerRole::Admin).public_key(&env));
    let members = vec![
        &env,
        MultisigMember::MlDsa65(member.clone()),
        MultisigMember::MlDsa65(member),
    ];
    let multisig = Signer::Multisig(
        MultisigSigner::new(BytesN::random(&env), members, 2),
        SignerRole::Admin,
    );
    env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), multisig],
            Vec::<Address>::new(&env),
        ),
    );
}
