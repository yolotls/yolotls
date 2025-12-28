//! HKDF Label utility for TLS 1.3
//! These are very easy to get wrong but here is a quick smol utility to spit them out.

/// HKDF Labels with SHA256 which are used in HKDF-Extract-Expand Key through TLS 1.3 Key Schedule
pub struct HkdfLabelSha256;

enum ServerOrClient {
    Server,
    Client,
}

impl HkdfLabelSha256 {
    pub fn tls13_c_e_traffic(ctx: &[u8; 32]) -> [u8; 54] {
        let mut r: [u8; 54] = [0; 54];
        const PREFIX: [u8; 17] = *b"tls13 c e traffic";
        r[1] = 53;
        r[2..18].copy_from_slice(&PREFIX);
        r[18] = 32;
        r[19..54].copy_from_slice(ctx);
        r
    }   
        
    pub const fn tls13_res_binder() -> [u8; 20] {
        //b"tls13 res binder
        [0, 32, 16, 116, 108, 115, 49, 51, 32, 0x72, 0x65, 0x73, 0x20, 0x62, 0x69, 0x6E, 0x64, 0x65, 0x72, 00]
    }
    /// Early secret has empty SHA256 ctx given no PSK
    #[inline]
    pub fn tls13_early_secret() -> [u8; 49] {
        //b"tls13 derived" + e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let r: [u8; 49] = [
            // Hashlen u16
            0, 32,
            // Len of of "tls13 derived" (1 byte)
            13,
            // tls13\s (6 bytes)
            116, 108, 115, 49, 51, 32,
            // derived (7 bytes)
            100, 101, 114, 105, 118, 101, 100,
            // Len of "ctx" (1 byte)
            32,
            // ctx = empty SHA256("") (32 bytes)
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb,
            0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4,
            0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
            0xb8, 0x55,
        ];

        assert_eq!(&r[3..16], b"tls13 derived");
        r
    }
    #[inline]
    pub fn tls13_server_secret_key(key_len: u8) -> [u8; 13] {
        //b"tls13 key"
        let r: [u8; 13] = [0, key_len, 9, 116, 108, 115, 49, 51, 32, 107, 101, 121, 0];
        assert_eq!(&r[3..12], b"tls13 key");
        r
    }
    #[inline]
    pub fn tls13_server_secret_iv() -> [u8; 12] {
        //b"tls13 iv"
        let r: [u8; 12] = [0, 12, 8, 116, 108, 115, 49, 51, 32, 105, 118, 00];
        assert_eq!(&r[3..11], b"tls13 iv");
        r
    }    
    fn _tls13_handshake_traffic(which: ServerOrClient, ctx: &[u8; 32]) -> [u8; 54] {
        
        let prefix: [u8; 18] = match which {
            ServerOrClient::Client => *b"tls13 c hs traffic",
            ServerOrClient::Server => *b"tls13 s hs traffic",
        };
        let mut r: [u8; 54] = [0; 54];
        r[1] = 32;
        r[2] = 18;
        r[3..21].copy_from_slice(&prefix);
        r[21] = 32;
        r[22..54].copy_from_slice(ctx);
        r
    }
    /// Handshake traffic uses Client+ServerHello Transcript hash for ctx
    #[inline]
    pub fn tls13_client_handshake_traffic(ctx: &[u8; 32]) -> [u8; 54] {
        Self::_tls13_handshake_traffic(ServerOrClient::Client, ctx)
    }
    #[inline]
    pub fn tls13_server_handshake_traffic(ctx: &[u8; 32]) -> [u8; 54] {
        Self::_tls13_handshake_traffic(ServerOrClient::Server, ctx)
    }
}


#[cfg(test)]
mod test_rfc8448 {
    // https://datatracker.ietf.org/doc/rfc8448/

    use super::*;
    use hex_literal::hex;
    use sha2::Sha256;
    use hkdf::{Hkdf, GenericHkdf, hmac::Hmac};

    const fn client_hello() -> &'static [u8; 196] {
        &hex!("01 00 00 c0 03 03 cb 34 ec b1 e7 81 63
         ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83
         02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b
         00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00
         12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23
         00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2
         3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a
         af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
         02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06
         02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01")
    }

    const fn server_hello() -> &'static [u8; 90] {
        &hex!("02 00 00 56 03 03 a6 af 06 a4 12 18 60
         dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
         d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88
         76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1
         dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04")
    }

    // Early secret without PSK is constructed using zero-hash-len
    fn early_secret_no_psk() -> ([u8; 32], GenericHkdf<Hmac<Sha256>>) {
        //*****************************************************
        //  early_secret = HKDF-Extract(salt: 00, key: 00...)
        //-----------------------------------------------------  
        let ikm: [u8; 32] = [0; 32];
        let salt: [u8; 1] = [0; 1];
        let (early_secret, hk) = Hkdf::<Sha256>::extract(Some(&salt[..]), &ikm);
        (early_secret.into(), hk)
    }

    // Check the early secret without PSK is correct
    #[test]
    fn early_secret_no_psk_ok() {
        let (ek, hk) = early_secret_no_psk();
        assert_eq!(ek, hex!("33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c
         e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a"));
    }

    // Check the derive secret is correct for SHA256
    fn derived_sha256() -> ([u8; 32], GenericHkdf<Hmac<Sha256>>) {
        let (ek, hk) = early_secret_no_psk();
        //*****************************************************
        // empty_hash = SHA256("")
        // derived_secret = HKDF-Expand-Label(key: early_secret, label: "derived", ctx: empty_hash, len: 32)
        //-----------------------------------------------------
        let label_derived = HkdfLabelSha256::tls13_early_secret();
        assert_eq!(label_derived, hex!("00 20 0d 74 6c 73 31 33 20 64 65 72 69 76 65 64
         20 e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4
         64 9b 93 4c a4 95 99 1b 78 52 b8 55"));
        
        let mut derived_secret: [u8; 32] = [0; 32];
        hk.expand(&label_derived, &mut derived_secret);
        (derived_secret, hk)
    }

    #[test]
    fn derived_sha256_ok() {
        let (derived_secret, hk) = derived_sha256();
        assert_eq!(derived_secret, hex!("6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba
         b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba"));        
    }

    fn shared_secret() -> &'static [u8; 32] {
        &hex!("8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d
         35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d")
    }
    
    fn handshake_secret() -> ([u8; 32], GenericHkdf<Hmac<Sha256>>) {
        let (derived_secret, derived_hk) = derived_sha256();
        let shared_secret = shared_secret();
        let (handshake_secret, hk) = Hkdf::<Sha256>::extract(Some(&derived_secret), shared_secret);
        (handshake_secret.into(), hk)
    }

    #[test]
    fn handshake_secret_ok() {
        let (handshake_secret, _hk) = handshake_secret();
        assert_eq!(handshake_secret, hex!("1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b
         01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac"));
    }

    // Test case derived Client+Server Hello handshake hash
    // Used to derive c/s hs traffic keys
    fn handshake_traffic_hash_input() -> &'static [u8; 32] {
        &hex!("86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed
         d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8")
    }
    
    #[test]
    fn label_tls13_server_handshake_traffic_label_ok() {
        let hello_hash = handshake_traffic_hash_input();
        let label = HkdfLabelSha256::tls13_server_handshake_traffic(hello_hash);
        
        assert_eq!(&label, &hex!("00 20 12 74 6c 73 31 33 20 73 20 68 73 20 74 72
         61 66 66 69 63 20 86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58
         ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8"));
    }

    //*****************************************************
    // server_secret = HKDF-Expand-Label(key: handshake_secret, label: "s hs traffic", ctx: hello_hash, len: 48)
    //-----------------------------------------------------
    fn server_hs_traffic_secret() -> ([u8; 32], GenericHkdf<Hmac<Sha256>>) {
        let (handshake_secret, hk) = handshake_secret();
        let mut server_secret: [u8; 32] = [0; 32];
        let hello_hash = handshake_traffic_hash_input();
        let label = HkdfLabelSha256::tls13_server_handshake_traffic(hello_hash);
        let mut server_secret: [u8; 32] = [0; 32];
        hk.expand(&label, &mut server_secret);
        (server_secret, hk)
    }

    #[test]
    fn server_hs_traffic_secret_ok() {
        let (server_secret, hk) = server_hs_traffic_secret();
        assert_eq!(&server_secret, &hex!("b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d
         37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38"));
    }

    #[test]
    fn server_hs_traffic_secret_key_ok() {
        let (server_secret, _hk) = server_hs_traffic_secret();

        let hk = Hkdf::<Sha256>::from_prk(&server_secret).expect("PRK should be large enough");
        let mut server_handshake_key: [u8; 16] = [0; 16];
        let key_label = HkdfLabelSha256::tls13_server_secret_key(16);
        assert_eq!(&key_label, &hex!("00 10 09 74 6c 73 31 33 20 6b 65 79 00"));
        hk.expand(&key_label, &mut server_handshake_key);
        assert_eq!(&server_handshake_key, &hex!("3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc"));
    }    

    #[test]
    fn server_hs_traffic_secret_iv_ok() {
        let (server_secret, _hk) = server_hs_traffic_secret();

        let hk = Hkdf::<Sha256>::from_prk(&server_secret).expect("PRK should be large enough");
        let mut server_handshake_iv: [u8; 12] = [0; 12];
        let iv_label = HkdfLabelSha256::tls13_server_secret_iv();
        assert_eq!(&iv_label, &hex!("00 0c 08 74 6c 73 31 33 20 69 76 00"));
        hk.expand(&iv_label, &mut server_handshake_iv);
        assert_eq!(&server_handshake_iv, &hex!("5d 31 3e b2 67 12 76 ee 13 00 0b 30"));
    }
}
