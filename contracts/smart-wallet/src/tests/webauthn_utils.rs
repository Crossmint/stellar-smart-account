use soroban_sdk::{Bytes, BytesN, Env};

pub struct WebAuthnTestUtils;

impl WebAuthnTestUtils {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_mock_webauthn_signature(
        &self,
        _challenge: &[u8],
    ) -> (Bytes, Bytes, BytesN<64>) {
        let env = Env::default();

        let authenticator_data = Bytes::from_array(&env, b"mock_authenticator_data_for_testing");

        let client_data_json_str = b"{\"type\":\"webauthn.get\",\"challenge\":\"dGVzdF9jaGFsbGVuZ2U\",\"origin\":\"https://test.example.com\"}";
        let client_data_json = Bytes::from_slice(&env, client_data_json_str);

        let signature = BytesN::from_array(&env, &[1u8; 64]);

        (authenticator_data, client_data_json, signature)
    }
}
