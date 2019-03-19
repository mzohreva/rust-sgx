use sgx_isa::{Keyrequest, Keyname, Report, Targetinfo};
use mbedtls::cipher::{Cipher, raw::{CipherId, CipherMode}};

#[test]
fn verify_mac() {
    let targetinfo = Targetinfo::from(Report::for_self());
    let report = Report::for_target(&targetinfo, &[0; 64]);

    let request = Keyrequest {
        keyname: Keyname::Report as _,
        keyid: report.keyid.clone(),
        ..Default::default()
    };
    let key = request.egetkey().unwrap();

    let mut mac_out = [0u8; 16];
    Cipher::new(CipherId::Aes, CipherMode::ECB, 128).unwrap()
        .cmac(&key, report.mac_data(), &mut mac_out).unwrap();

    assert_eq!(mac_out, report.mac);
}
