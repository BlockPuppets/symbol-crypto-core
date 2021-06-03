// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(test)]
pub mod tests {
    use hex::ToHex;

    use symbol_crypto_core::prelude::{H256, Keypair, PrivateKey, Signature};

    const KEYPAIR_BYTES_SIZE: usize = 64;
    const SIGNATURE_SIZE: usize = 64;

    pub mod tests_sym {
        use symbol_crypto_core::prelude::KpSym;

        use super::*;

        pub mod tests_keypair {
            use super::*;

            const PRIVATE_KEYS: [&str; 5] = [
                "575dbb3062267eff57c970a336ebbc8fbcfe12c5bd3ed7bc11eb0481d7704ced",
                "5b0e3fa5d3b49a79022d7c1e121ba1cbbf4db5821f47ab8c708ef88defc29bfe",
                "738ba9bb9110aea8f15caa353aca5653b4bdfca1db9f34d0efed2ce1325aeeda",
                "e8bf9bc0f35c12d8c8bf94dd3a8b5b4034f1063948e3cc5304e55e31aa4b95a6",
                "c325ea529674396db5675939e7988883d59a5fc17a28ca977e3ba85370232a83",
            ];

            const PUBLIC_KEYS: [&str; 5] = [
                "2E834140FD66CF87B254A693A2C7862C819217B676D3943267156625E816EC6F",
                "4875FD2E32875D1BC6567745F1509F0F890A1BF8EE59FA74452FA4183A270E03",
                "9F780097FB6A1F287ED2736A597B8EA7F08D20F1ECDB9935DE6694ECF1C58900",
                "0815926E003CDD5AF0113C0E067262307A42CD1E697F53B683F7E5F9F57D72C9",
                "3683B3E45E76870CFE076E47C2B34CE8E3EAEC26C8AA7C1ED752E3E840AF8A27",
            ];

            const INVALID_PRIVATE_KEYS: [&str; 3] = [
                "",                                                                   // empty
                "53C659B47C176A70EB228DE5C0A0FF391282C96640C2A42CD5BBD0982176AB",     // short
                "53C659B47C176A70EB228DE5C0A0FF391282C96640C2A42CD5BBD0982176AB1BBB", // long
            ];

            #[test]
            fn construction() {
                for (i, private_key_hex) in PRIVATE_KEYS.iter().enumerate() {
                    let expected_public_key_hex: &str = PUBLIC_KEYS[i];

                    let keypair: Keypair<KpSym> =
                        Keypair::<KpSym>::from_hex_private_key(private_key_hex).unwrap();

                    assert_eq!(
                        private_key_hex.to_string(),
                        keypair.private_key().encode_hex::<String>()
                    );
                    assert_eq!(
                        expected_public_key_hex,
                        keypair.public_key().encode_hex_upper::<String>()
                    );
                }
            }

            #[test]
            fn test_invalid_private_key() {
                INVALID_PRIVATE_KEYS.iter().for_each(move |private_key| {
                    let keypair = Keypair::<KpSym>::from_hex_private_key(private_key);
                    assert!(keypair.is_err());
                });
            }

            #[test]
            #[should_panic(expected = "private_key it's not hex.")]
            fn test_invalid_private_key_panic() {
                INVALID_PRIVATE_KEYS.iter().for_each(|private_key| {
                    Keypair::<KpSym>::from_hex_private_key(private_key).unwrap();
                });
            }

            #[test]
            fn test_keypair_bytes() {
                let keypair_bytes: Vec<u8> = Vec::from([
                    58, 79, 97, 31, 86, 53, 89, 175, 32, 20, 61, 46, 11, 176, 157, 53, 199, 169,
                    121, 55, 154, 48, 210, 168, 189, 1, 3, 22, 213, 61, 56, 160, 192, 202, 251, 77,
                    152, 114, 54, 145, 98, 218, 232, 91, 60, 242, 149, 161, 161, 226, 28, 151, 125,
                    139, 119, 145, 170, 154, 209, 82, 238, 124, 253, 65,
                ]);

                let keypair: Keypair<KpSym> = Keypair::<KpSym>::from_bytes(&keypair_bytes).unwrap();

                assert_eq!(keypair.to_bytes().len(), KEYPAIR_BYTES_SIZE);
                assert_eq!(keypair_bytes, keypair.to_bytes().to_vec());
                assert_eq!(&keypair_bytes[0..32], keypair.private_key().as_bytes());
                assert_eq!(&keypair_bytes[32..], keypair.public_key().as_bytes());
            }
        }

        pub mod tests_sign {
            use super::*;

            const SYMBOL_PRIVATE_KEY: [&str; 5] = [
                "abf4cf55a2b3f742d7543d9cc17f50447b969e6e06f5ea9195d428ab12b7318d",
                "6aa6dad25d3acb3385d5643293133936cdddd7f7e11818771db1ff2f9d3f9215",
                "8e32bc030a4c53de782ec75ba7d5e25e64a2a072a56e5170b77a4924ef3c32a9",
                "c83ce30fcb5b81a51ba58ff827ccbc0142d61c13e2ed39e78e876605da16d8d7",
                "2da2a0aae0f37235957b51d15843edde348a559692d8fa87b94848459899fc27",
            ];
            const SYMBOL_DATA: [&str; 5] = [
                "8ce03cd60514233b86789729102ea09e867fc6d964dea8c2018ef7d0a2e0e24bf7e348e917116690b9",
                "e4a92208a6fc52282b620699191ee6fb9cf04daf48b48fd542c5e43daa9897763a199aaa4b6f10546109f47ac3564fade0",
                "13ed795344c4448a3b256f23665336645a853c5c44dbff6db1b9224b5303b6447fbf8240a2249c55",
                "a2704638434e9f7340f22d08019c4c8e3dbee0df8dd4454a1d70844de11694f4c8ca67fdcb08fed0cec9abb2112b5e5f89",
                "d2488e854dbcdfdb2c9d16c8c0b2fdbc0abb6bac991bfe2b14d359a6bc99d66c00fd60d731ae06d0",
            ];
            const EXPECTED_SIGNATURE: [&str; 5] = [
                "31D272F0662915CAC43AB7D721CAF65D8601F52B2E793EA1533E7BC20E04EA97B74859D9209A7B18DFECFD2C4A42D6957628F5357E3FB8B87CF6A888BAB4280E",
                "F21E4BE0A914C0C023F724E1EAB9071A3743887BB8824CB170404475873A827B301464261E93700725E8D4427A3E39D365AFB2C9191F75D33C6BE55896E0CC00",
                "939CD8932093571E24B21EA53F1359279BA5CFC32CE99BB020E676CF82B0AA1DD4BC76FCDE41EF784C06D122B3D018135352C057F079C926B3EFFA7E73CF1D06",
                "9B4AFBB7B96CAD7726389C2A4F31115940E6EEE3EA29B3293C82EC8C03B9555C183ED1C55CA89A58C17729EFBA76A505C79AA40EC618D83124BC1134B887D305",
                "7AF2F0D9B30DE3B6C40605FDD4EBA93ECE39FA7458B300D538EC8D0ABAC1756DEFC0CA84C8A599954313E58CE36EFBA4C24A82FD6BB8127023A58EFC52A8410A",
            ];

            #[test]
            fn test_sign() {
                let payload = H256::random();
                let keypair: Keypair<KpSym> = Keypair::<KpSym>::random();
                // Act:
                let signature = keypair.sign(&payload.as_bytes());

                assert_ne!(signature, Signature::zero());
            }

            #[test]
            fn test_sign_verify_vector() {
                for (i, private_key_hex) in SYMBOL_PRIVATE_KEY.iter().enumerate() {
                    let keypair: Keypair<KpSym> =
                        Keypair::<KpSym>::from_hex_private_key(private_key_hex).unwrap();

                    let payload = hex::decode(SYMBOL_DATA[i]).unwrap();

                    let signature = keypair.sign(&payload);
                    assert_eq!(
                        signature.encode_hex_upper::<String>(),
                        EXPECTED_SIGNATURE[i].to_string()
                    );
                }
            }

            #[test]
            fn test_sing_same_signature_same_key_pairs() {
                let private_key = PrivateKey::random().encode_hex::<String>();
                let key_pair1 = Keypair::<KpSym>::from_hex_private_key(&private_key).unwrap();
                let key_pair2 = Keypair::<KpSym>::from_hex_private_key(&private_key).unwrap();

                let payload = H256::random();

                let signature1 = key_pair1.sign(payload.as_bytes());
                let signature2 = key_pair2.sign(payload.as_bytes());

                assert_eq!(signature1, signature2);
            }

            #[test]
            fn test_sign_different_signature_different_key_pairs() {
                let key_pair1 = Keypair::<KpSym>::random();
                let key_pair2 = Keypair::<KpSym>::random();

                let payload = H256::random();

                let signature1 = key_pair1.sign(payload.as_bytes());
                let signature2 = key_pair2.sign(payload.as_bytes());

                assert_ne!(signature1, signature2);
            }
        }

        pub mod tests_verify {
            use super::*;

            #[test]
            fn test_verify_data_signed_same_key_pairs() {
                let key_pair = Keypair::<KpSym>::random();
                let payload = H256::random();

                let signature = key_pair.sign(payload.as_bytes());

                let is_verified = key_pair.verify(payload.as_bytes(), signature);

                assert!(is_verified.is_ok())
            }

            #[test]
            fn test_verify_data_signed_different_key_pairs() {
                let key_pair1 = Keypair::<KpSym>::random();
                let key_pair2 = Keypair::<KpSym>::random();

                let payload = H256::random();

                let signature = key_pair1.sign(payload.as_bytes());

                let is_verified = key_pair2.verify(payload.as_bytes(), signature);

                assert!(is_verified.is_err())
            }

            #[test]
            fn test_verify_signature_has_been_modified() {
                let key_pair = Keypair::<KpSym>::random();

                let payload = H256::random();

                let mut i = 0;
                while i < SIGNATURE_SIZE {
                    let mut signature = key_pair.sign(payload.as_bytes());
                    signature.0[i] ^= 0xff;
                    i += 4;

                    let is_verified = key_pair.verify(payload.as_bytes(), signature);
                    assert!(is_verified.is_err());
                }
            }

            #[test]
            fn test_verify_payload_has_been_modified() {
                let key_pair = Keypair::<KpSym>::random();

                let mut payload = H256::random();

                let mut i = 0;
                while i < payload.as_bytes().len() {
                    let signature = key_pair.sign(payload.as_bytes());
                    payload.0[i] ^= 0xff;
                    i += 4;

                    let is_verified = key_pair.verify(payload.as_bytes(), signature);
                    assert!(is_verified.is_err());
                }
            }

            #[test]
            fn test_verify_zero_public_key() {
                let mut key_pair = Keypair::<KpSym>::random();
                key_pair.0.public_key.0.fill(0);

                let payload = H256::random();

                let signature = key_pair.sign(payload.as_bytes());
                let is_verified = key_pair.verify(payload.as_bytes(), signature);

                assert!(is_verified.is_err());
            }

            #[test]
            fn test_verify_public_key_does_not_correspond_to_private_key() {
                let mut key_pair = Keypair::<KpSym>::random();

                let payload = H256::random();

                let signature = key_pair.sign(payload.as_bytes());

                let mut i = 0;

                while i < key_pair.0.public_key.as_bytes().len() {
                    key_pair.0.public_key.0[i] ^= 0xff;
                    i += 4;
                }

                let is_verified = key_pair.verify(payload.as_bytes(), signature);

                assert!(is_verified.is_err());
            }
        }
    }

    pub mod tests_nis1 {
        use symbol_crypto_core::prelude::KpNis1;

        use super::*;

        pub mod tests_keypair {
            use super::*;

            #[test]
            fn test_create_from_hex_private_key() {
                let private_key =
                    "c9fb7f16b738b783be5192697a684cba4a36adb3d9c22c0808f30ae1d85d384f";
                let expected_public_key =
                    "ed9bf729c0d93f238bc4af468b952c35071d9fe1219b27c30dfe108c2e3db030";

                // Act:
                let kp = Keypair::<KpNis1>::from_hex_private_key(private_key).unwrap();

                assert_eq!(kp.public_key().encode_hex::<String>(), expected_public_key);
            }
        }

        pub mod tests_sign {
            use super::*;

            #[test]
            fn test_sign_data_with_private_key() {
                let private_key =
                    "abf4cf55a2b3f742d7543d9cc17f50447b969e6e06f5ea9195d428ab12b7318d";
                let expected_signature = "d9cec0cc0e3465fab229f8e1d6db68ab9cc99a18cb0435f70deb6100948576cd5c0aa1feb550bdd8693ef81eb10a556a622db1f9301986827b96716a7134230c";

                // Act:
                let kp = Keypair::<KpNis1>::from_hex_private_key(private_key).unwrap();

                let data = hex::decode("8ce03cd60514233b86789729102ea09e867fc6d964dea8c2018ef7d0a2e0e24bf7e348e917116690b9").unwrap();

                let signature = kp.sign(&data);

                // Assert:
                assert_eq!(signature.encode_hex::<String>(), expected_signature);
            }
        }

        pub mod tests_verify {
            use std::str::FromStr;

            use super::*;

            #[test]
            fn test_verify_a_signature() {
                // Arrange:
                let signer = "ed9bf729c0d93f238bc4af468b952c35071d9fe1219b27c30dfe108c2e3db030";
                let data = b"NEM is awesome !";
                let signature =
                    Signature::from_str
                        ("d940d229dc57c7fca77e3232e09914e41de5c5d175de3ef58be3b35692514ea2337ef514a059e742a15ee5d02a09fd0d3803e9379d9e008be128a49dd554b600").unwrap();
                // Act:
                let kp = Keypair::<KpNis1>::from_hex_private_key(signer).unwrap();

                let signature = kp.verify(data, signature);

                assert!(signature.is_ok());
            }

            #[test]
            fn test_signature_has_invalid_length() {
                let signature =
                    Signature::from_str
                        ("f72d5abbf48a53e3c7c9c402bcb1b0a855821d5ef970dd5357b9899034d0c8dc177cef8e5924607ca325041b57db33628bd2f010c2474ff18");

                assert!(signature.is_err());
            }

            #[test]
            fn test_signature_is_not_strictly_hexadecimal() {
                let signature =
                    Signature::from_str
                        ("f72d5abbf48a53e3c7c9c402bcb1b0a855821d5ef970dd5357b9899034d0c8dc177cef8e5924607ca325041b57db33628bd2f010c2474ff18fff7b509a1wwwww");

                assert!(signature.is_err());
            }

            #[test]
            fn test_wrong_public_key_provided() {
                // Arrange:
                let signer = "0257b05f601ff829fdff84956fb5e3c65470a62375a1cc285779edd5ca3b42f6";
                let data = b"NEM is awesome !";
                let signature =
                    Signature::from_str
                        ("d940d229dc57c7fca77e3232e09914e41de5c5d175de3ef58be3b35692514ea2337ef514a059e742a15ee5d02a09fd0d3803e9379d9e008be128a49dd554b600").unwrap();
                // Act:
                let kp = Keypair::<KpNis1>::from_hex_private_key(signer).unwrap();

                let signature = kp.verify(data, signature);

                assert!(signature.is_err());
            }

            #[test]
            fn test_data_is_not_corresponding_to_signature_provided() {
                // Arrange:
                let signer = "ed9bf729c0d93f238bc4af468b952c35071d9fe1219b27c30dfe108c2e3db030";
                let data = b"NEM is really awesome !";
                let signature =
                    Signature::from_str
                        ("d940d229dc57c7fca77e3232e09914e41de5c5d175de3ef58be3b35692514ea2337ef514a059e742a15ee5d02a09fd0d3803e9379d9e008be128a49dd554b600").unwrap();
                // Act:
                let kp = Keypair::<KpNis1>::from_hex_private_key(signer).unwrap();

                let signature = kp.verify(data, signature);

                assert!(signature.is_err());
            }

            #[test]
            fn test_signature_is_not_corresponding_to_data_provided() {
                // Arrange:
                let signer = "ed9bf729c0d93f238bc4af468b952c35071d9fe1219b27c30dfe108c2e3db030";
                let data = b"NEM is awesome !";
                let signature =
                    Signature::from_str
                        ("f67e5abbf48a53e3c7c9c402bcb1b0a855821d5ef970dd5357b9899034d0c8dc177cef8e5924607ca325041b57db33628bd2f010c2474ff18fff7b509a1eeacb").unwrap();
                // Act:
                let kp = Keypair::<KpNis1>::from_hex_private_key(signer).unwrap();

                let signature = kp.verify(data, signature);

                assert!(signature.is_err());
            }
        }
    }
}
