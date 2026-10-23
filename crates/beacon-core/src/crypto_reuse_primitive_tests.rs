#[test]
fn synthetic_reused_chacha_nonce_discloses_only_payload_xor() {
    let cipher=SessionCipher::new(&[7;32]);let nonce=[9;12];
    let p=[3u8;32];let q=[10u8;32];
    let a=cipher.seal(&nonce,b"synthetic",&p).unwrap();let b=cipher.seal(&nonce,b"synthetic",&q).unwrap();
    assert_eq!(a.len(),48);assert_eq!(b.len(),48);
    // Explicit independent expected payload-XOR bytes; authentication tags excluded.
    assert_eq!(a[..32].iter().zip(&b[..32]).map(|(a,b)|a^b).collect::<Vec<_>>(),vec![9;32],"ChaCha reused nonce must expose payload XOR control");
    let mut modified=a.clone();modified[0]^=1;
    assert!(cipher.open(&nonce,b"synthetic",&modified).is_err(),"authentication failure is a separate property from nonce reuse");
    assert_eq!(cipher.open(&nonce,b"synthetic",&a).unwrap(),p);
}
