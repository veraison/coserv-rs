// SPDX-License-Identifier: Apache-2.0

use crate::coserv::{CoseAlgorithm, CoseKey, CoseKeyOwner, CoseSigner, CoseVerifier};
use corim_rs::CorimError;
use jsonwebkey as jwk;
use std::str::FromStr;

/// Wrapper around [corim_rs::OpensslSigner]
pub struct OpensslSigner(corim_rs::OpensslSigner);

impl CoseKeyOwner for OpensslSigner {
    fn to_cose_key(&self) -> CoseKey {
        self.0.to_cose_key()
    }
}

/// Wrapper around [corim_rs::OpensslSigner]
pub struct OpensslVerifier(corim_rs::OpensslSigner);

impl CoseKeyOwner for OpensslVerifier {
    fn to_cose_key(&self) -> CoseKey {
        self.0.to_cose_key()
    }
}

impl OpensslSigner {
    /// Construct [OpensslSigner] from PEM encoded private key
    pub fn from_pem(key: &str) -> Result<Self, CorimError> {
        Ok(Self(corim_rs::OpensslSigner::private_key_from_pem(
            key.as_bytes(),
        )?))
    }

    /// Construct [OpensslSigner] from JWK encoded private key
    pub fn from_jwk(key: &str) -> Result<Self, CorimError> {
        Ok(Self(corim_rs::OpensslSigner::private_key_from_pem(
            jwk_to_pem(key)?.as_bytes(),
        )?))
    }

    /// Construct [OpensslSigner] from COSE_Key
    pub fn from_cose_key(key: &[u8]) -> Result<Self, CorimError> {
        let key: CoseKey = ciborium::from_reader(key).map_err(CorimError::custom)?;
        Ok(OpensslSigner(key.into()))
    }
}

impl CoseSigner for OpensslSigner {
    fn sign(&self, alg: CoseAlgorithm, data: &[u8]) -> Result<Vec<u8>, CorimError> {
        self.0.sign(alg, data)
    }
}

impl OpensslVerifier {
    /// Construct [OpensslVerifier] from PEM encoded public key
    pub fn from_pem(key: &str) -> Result<Self, CorimError> {
        Ok(Self(corim_rs::OpensslSigner::public_key_from_pem(
            key.as_bytes(),
        )?))
    }

    /// Construct [OpensslVerifier] from JWK encoded public key
    pub fn from_jwk(key: &str) -> Result<Self, CorimError> {
        Ok(Self(corim_rs::OpensslSigner::public_key_from_pem(
            jwk_to_pem(key)?.as_bytes(),
        )?))
    }

    /// Construct [OpensslVerifier] from COSE_Key
    pub fn from_cose_key(key: &[u8]) -> Result<Self, CorimError> {
        let mut key: CoseKey = ciborium::from_reader(key).map_err(CorimError::custom)?;
        (key.d, key.k) = (None, None); // remove private fields
        Ok(OpensslVerifier(key.into()))
    }
}

impl CoseVerifier for OpensslVerifier {
    fn verify_signature(
        &self,
        alg: CoseAlgorithm,
        sig: &[u8],
        data: &[u8],
    ) -> Result<(), CorimError> {
        self.0.verify_signature(alg, sig, data)
    }
}

fn jwk_to_pem(key: &str) -> Result<String, CorimError> {
    jwk::JsonWebKey::from_str(key)
        .map_err(CorimError::custom)?
        .key
        .try_to_pem()
        .map_err(CorimError::custom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coserv::Coserv;

    #[rustfmt::skip]
    const COSERV: [u8; 94] = [
0xA3, // map(3)
    0x00, // key 0 (profile)
    0x63, 0x66, 0x6F, 0x6F, // "foo"
    0x01, // key 1 (query)
    0xA3, // map (3)
        0x00, // key 0 (artifact type)
        0x02, // 2 (reference values)
        0x01, // key 1 (environment selector)
        0xA1, // map(1)
            0x01, // key 1 (instance)
            0x82, // array(2)
                0x81, // array(1)
                    0xD9, 0x02, 0x30, // tag(560)
                    0x43, // bytes(3)
                        0x00, 0x01, 0x02,
                0x81, // array(1)
                    0xD9, 0x02, 0x30, // tag(560)
                    0x43, // bytes(3)
                        0x01, 0x02, 0x03, 
        0x02, // key 2 (result type)
        0x00, // collected artifacts
    0x02, // key 2 (results)
        0xA2, // map (2)
            0x00, // key 0 (reference value quads)
            0x81, // array(2)
                0xA2, // map(2)
                    0x01, // key 1 (authorities)
                    0x81, // array(1)
                        0xD9, 0x02, 0x30, // tag(560)
                        0x42, // bytes(2)
                            0x00, 0x01, 
                    0x02, // key 2 (rv triples)
                    0x82, // array(2)
                        0xA1, // map(1)
                            0x01, // key 1
                            0xD9, 0x02, 0x30, // tag(560)
                            0x43, // bytes(3)
                                0x00, 0x01, 0x02,
                        0x81, // array(1)
                            0xA1, // map(1)
                                0x01, // key 1
                                0xA1, // map(1)
                                    0x0B, //key 11
                                    0x63, 0x66, 0x6F, 0x6F, // "foo"

            0x0A, //key 10 (expiry)
            0xC0, // tag(0)
                0x78, 0x19, // text(25)
                    0x32, 0x30, 0x32, 0x35, 0x2D, 0x31, 0x31, 0x2D, 0x32, 0x31, 0x54, 0x31, 0x36, 0x3A, 0x30, 0x38, 0x3A, 0x35, 0x36, 0x2B, 0x30, 0x35, 0x3A, 0x33, 0x30,
    ];

    #[rustfmt::skip]
    const PRIV_COSE: [u8; 112] = [
0xA6, // map(6)
    0x01, // kty
    0x02, // 2 (EC2)
    0x03, // alg
    0x26, // -7
    0x20, // -1 (crv)
    0x01, // 1 (P-256)
    0x21, // -2 (x)
    0x58, 0x20, // bytes(32)
    0xfe, 0x03, 0xec, 0xb0, 0xb2, 0x22, 0x2E, 0x71, 0x74, 0x5e, 0xb4, 0xc6, 0x53, 0xbd, 0xD7, 0x30, 0xa9, 0x53, 0x22, 0x4e, 0x10, 0x85, 0x4F, 0x34, 0xb6, 0xd5, 0xf3, 0x27, 0xbc, 0x1a, 0x4E, 0x9a,
    0x22, // -3 (y)
    0x58, 0x20, // bytes(32)
    0x1e, 0x08, 0x9b, 0x0F, 0xc4, 0x6d, 0xa1, 0xcc, 0xcb, 0x94, 0x90, 0x73, 0x0e, 0x2e, 0xb6, 0x71, 0x36, 0x9c, 0x31, 0x1F, 0x4d, 0x38, 0xbf, 0x26, 0x87, 0xa4, 0x5f, 0x53, 0x61, 0x37, 0x97, 0x09,
    0x23, // -4 (d)
    0x58, 0x20, // bytes(32)
    0x67, 0x17, 0xc8, 0xa9, 0x65, 0x60, 0x9f, 0xcb, 0x97, 0x48, 0xd4, 0x23, 0xd2, 0xdf, 0x2b, 0xfe, 0xEE, 0xa2, 0x4b, 0xc5, 0x89, 0xb8, 0xac, 0x5b, 0x99, 0x4c, 0xf0, 0x36, 0x5a, 0x44, 0xef, 0xad,
    ];

    #[rustfmt::skip]
    const PUB_COSE: [u8; 77] = [
0xA5, // map(5)
    0x01, // kty
    0x02, // 2 (EC2)
    0x03, // alg
    0x26, // -7
    0x20, // -1 (crv)
    0x01, // 1 (P-256)
    0x21, // -2 (x)
    0x58, 0x20, // bytes(32)
    0xfe, 0x03, 0xec, 0xb0, 0xb2, 0x22, 0x2E, 0x71, 0x74, 0x5e, 0xb4, 0xc6, 0x53, 0xbd, 0xD7, 0x30, 0xa9, 0x53, 0x22, 0x4e, 0x10, 0x85, 0x4F, 0x34, 0xb6, 0xd5, 0xf3, 0x27, 0xbc, 0x1a, 0x4E, 0x9a,
    0x22, // -3 (y)
    0x58, 0x20, // bytes(32)
    0x1e, 0x08, 0x9b, 0x0F, 0xc4, 0x6d, 0xa1, 0xcc, 0xcb, 0x94, 0x90, 0x73, 0x0e, 0x2e, 0xb6, 0x71, 0x36, 0x9c, 0x31, 0x1F, 0x4d, 0x38, 0xbf, 0x26, 0x87, 0xa4, 0x5f, 0x53, 0x61, 0x37, 0x97, 0x09,

    ];

    const PRIV_PEM: &str = r#"
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGcXyKllYJ/Ll0jUI9LfK/7uokvFibisW5lM8DZaRO+toAoGCCqGSM49
AwEHoUQDQgAE/gPssLIiLnF0XrTGU73XMKlTIk4QhU80ttXzJ7waTpoeCJsPxG2h
zMuUkHMOLrZxNpwxH004vyaHpF9TYTeXCQ==
-----END EC PRIVATE KEY-----
"#;

    const PUB_PEM: &str = r#"
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/gPssLIiLnF0XrTGU73XMKlTIk4Q
hU80ttXzJ7waTpoeCJsPxG2hzMuUkHMOLrZxNpwxH004vyaHpF9TYTeXCQ==
-----END PUBLIC KEY-----
"#;

    const PRIV_JWK: &str = r#"
{
  "kty": "EC",
  "crv": "P-256",
  "alg": "ES256",
  "d": "ZxfIqWVgn8uXSNQj0t8r_u6iS8WJuKxbmUzwNlpE760",
  "x": "_gPssLIiLnF0XrTGU73XMKlTIk4QhU80ttXzJ7waTpo",
  "y": "HgibD8RtoczLlJBzDi62cTacMR9NOL8mh6RfU2E3lwk"
}
"#;

    const PUB_JWK: &str = r#"
{
  "kty": "EC",
  "crv": "P-256",
  "alg": "ES256",
  "x": "_gPssLIiLnF0XrTGU73XMKlTIk4QhU80ttXzJ7waTpo",
  "y": "HgibD8RtoczLlJBzDi62cTacMR9NOL8mh6RfU2E3lwk"
}
"#;

    #[test]
    fn test_sign_verify_pem() {
        let resp = Coserv::from_cbor(&COSERV[..]).unwrap();
        let signer = OpensslSigner::from_pem(PRIV_PEM).unwrap();
        let signed_resp = resp.sign(&signer, CoseAlgorithm::ES256).unwrap();

        let verifier = OpensslVerifier::from_pem(PUB_PEM).unwrap();
        let res = Coserv::verify_and_extract(&verifier, signed_resp.as_slice());
        assert!(res.is_ok());
    }

    #[test]
    fn test_sign_verify_jwk() {
        let resp = Coserv::from_cbor(&COSERV[..]).unwrap();
        let signer = OpensslSigner::from_jwk(PRIV_JWK).unwrap();
        let signed_resp = resp.sign(&signer, CoseAlgorithm::ES256).unwrap();

        let verifier = OpensslVerifier::from_jwk(PUB_JWK).unwrap();
        let res = Coserv::verify_and_extract(&verifier, signed_resp.as_slice());
        assert!(res.is_ok());
    }

    #[test]
    fn test_sign_verify_cose() {
        let resp = Coserv::from_cbor(&COSERV[..]).unwrap();
        let signer = OpensslSigner::from_cose_key(&PRIV_COSE[..]).unwrap();
        let signed_resp = resp.sign(&signer, CoseAlgorithm::ES256).unwrap();

        let verifier = OpensslVerifier::from_cose_key(&PUB_COSE[..]).unwrap();
        let res = Coserv::verify_and_extract(&verifier, signed_resp.as_slice());
        assert!(res.is_ok());
    }
}
