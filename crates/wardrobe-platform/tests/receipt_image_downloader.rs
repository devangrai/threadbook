use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use image::codecs::png::{CompressionType, FilterType, PngEncoder};
use image::ImageEncoder;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;
use wardrobe_core::{ReceiptImageCandidateEligibilityV1, SourceId, MAX_RECEIPT_IMAGE_CANDIDATES};
use wardrobe_platform::{
    parse_receipt_bundle_v1, ReceiptImageAddressPolicy, ReceiptImageDownloadRequestV1,
    ReceiptImageFailureCodeV1, ReceiptImageResolver, ReqwestReceiptImageDownloader,
    SealedProductionAddressPolicy, SystemClock,
};

const FIXTURE_CERT_DER: &str = "MIIDWDCCAkCgAwIBAgIUMfBfc+6pYOfBaijGM1Hh8d6du/gwDQYJKoZIhvcNAQELBQAwGjEYMBYGA1UEAwwPZml4dHVyZS5pbnZhbGlkMB4XDTI2MDcxNTA0MTk0OVoXDTM2MDcxMjA0MTk0OVowGjEYMBYGA1UEAwwPZml4dHVyZS5pbnZhbGlkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0cO1+n5QmCZu0HnVEa0VpIrBc5ApyzihX7QvIWr6w0FmQ36QdsGcxTLWShPm/d56LbzduskIorfhqYVp+dCF3HDXle27Fmb0GRQ9H6VN8S4oFooixV83W4DthzZG69ANervL8A8aBAkwXID2io6FR0h7nZbyVKOUSsbE/uMnC9PewX7CycRjIdD4pld0bdOmJkwfLKiB1SAdL1udnYtYJs08yLhOqkZx6iWC2E6oixtpaNqjSKiHMdFgooqX8XDGqvfROJ5Ltl9wYkJ0retBPDrPHBzYYcTMRIUWRYoTzQwAaJCKQllkye7KeaZ25cJuR6i8Zu6Ub3Z4WO9T5C6Q+wIDAQABo4GVMIGSMB0GA1UdDgQWBBR3GKJs3DQZg4UdP9mTXTwpF8OHsDAfBgNVHSMEGDAWgBR3GKJs3DQZg4UdP9mTXTwpF8OHsDAaBgNVHREEEzARgg9maXh0dXJlLmludmFsaWQwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZIhvcNAQELBQADggEBALLH/hS88lsjZLkhplhS+lAdTcMHl49FYygnMaZj3Um8NTzSFQhJK1MxSqmu0sNGZSXr3Y61/U05OmVZJlP8a7wy1pBOxI1X+IPB80PT2m9EM8QUIfiow+QhMMGfYzUYDxL7l8RnF+gy7Le5Uvf3/37xzkZUjHpfFZiqfFuTWak2DueOUFVdsvibQV9jfUEdcJOU8in1vjNmoefdwkh0EMXKRwGCgElEzxm4HoZXPWTnMW0pJP2xDO3FGVro8iKaeM96rCbcBjjed0ksdMx1ML/NGXX0dh7Rc9MmIJgD7KDkPmUhNMoCRdT/TjSUPVL8ZkX8lRPvn14hjQRsu8KAY74=";
const FIXTURE_KEY_DER: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDRw7X6flCYJm7QedURrRWkisFzkCnLOKFftC8havrDQWZDfpB2wZzFMtZKE+b93notvN26yQiit+GphWn50IXccNeV7bsWZvQZFD0fpU3xLigWiiLFXzdbgO2HNkbr0A16u8vwDxoECTBcgPaKjoVHSHudlvJUo5RKxsT+4ycL097BfsLJxGMh0PimV3Rt06YmTB8sqIHVIB0vW52di1gmzTzIuE6qRnHqJYLYTqiLG2lo2qNIqIcx0WCiipfxcMaq99E4nku2X3BiQnSt60E8Os8cHNhhxMxEhRZFihPNDABokIpCWWTJ7sp5pnblwm5HqLxm7pRvdnhY71PkLpD7AgMBAAECggEAZ+n+MpN0tYsEhn50UQdfm12pq+gU7Dmnp9OJLZLjmurBEFqYklwjn4UppxTo74bRG+teJHQGtSVGw0X2U+07AxNbmUhl0Bk8f1gJV636SKpG7bOMuh4LPGdIRB1dUOCGbPCvfMLebnVm4cx5VfZ4i/GaW101uzw18D07xdEdvLtZG1t4O5peJ7xo1JIqPO0PWBEqftQaQma4bNk4+gGQ0wRZeKYvSEf3JR36SEeXfHzrfESao158rSkTOX6SXTHcHSh7VEBy1k+yFMqHD6RMPBIHvaDp9VfL1zL11lZ+8TSp0PCjgZ46mTLI3J9NiIbOWIob71R62KtKs+VOl0WIUQKBgQDoy4CeYOE3dsbNuCRw1JF75kqqGZBeR5xz6yMH/mRXyRr7FM4p/+obfQ1zYmw+O3Klq0Qnjg8fkmbFTiVfnoBJuM5tsI9DePpNke9BAGw0F3tiCeOmCSZdAjvhFmPabJRpgGke3N/9/47lLh+l9CHe3qBPydBoUqdzOqxF1iYrdwKBgQDmrIOgKrtSIZS4srixYRcL+lQKzFwNnL2gYBsUW7bN/a1dLsCm6Lj6JTQzDVgEPq/opktYo92EO5+nuH3KlHqsW/3j7Ybg0uDBsjbxTIuW+TQo3fykTPdu32JCN0zJzdJjFrBNdlW2JsMbQANSY2BB85ZqraxnVj5A0LweuDGfnQKBgFAeMY7QctJe237TgB8g2U0V7d5q2+fGp46xfyXyJGCeAt4kw+tqewyo1ic+2Vf1p7hioBso5gWMojgHdA9bgnVc2BaiLDwhd6uYrQnm9lZbOoh8NM/g2EYsTaViykzTD6Tbn9ISXDiTan9vh07bHYkRf4TWRRaSU7TxnXaPhCVzAoGAK9lbZBT7as9rX/jJVx6nrOU3GJ5kWUoUWeoq+6G7jEjOrcn3YUMX9qUf2RyOQLBR7B3AcOclcr+Kx+0wLFQxRZZvGubKHu63PtrLyu7MEjTpD2OzZOAkoPThzsiIVkxD1AY6GV+HR4ryx7lRaFXvtFnDnB/LiBFC4DtNp2FIPZkCgYEAnmvXRKWeFMvCZ4hh/eRqfI4G8+3KEvsT3xOeo2RJlMQs3Xp1pgd5v4aCTZ6RCeN7bPk8ZXz5Z3RfINkO+v1jKRXUb3VwxPdec5RphP0mEUurr/bFMXgK/vY1w1Qry32+aenI6pZ+cm7aQ8I/ueqo4gIjIu7MACdGiZ87AyM5Hr4=";
const FIXTURE_LEAF_CERT_DER: &str = "MIIDVTCCAj2gAwIBAgIUHhMl6YBCKxpfUL0zEHYv1OPf3g0wDQYJKoZIhvcNAQELBQAwGjEYMBYGA1UEAwwPZml4dHVyZS5pbnZhbGlkMB4XDTI2MDcxNTA0MjI0M1oXDTM2MDcxMjA0MjI0M1owGjEYMBYGA1UEAwwPZml4dHVyZS5pbnZhbGlkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyUu4neGmJrTG8FLRNHb3eoEt9mi3r82r4Cg3hvqA5zStwcC7z1IQymM44TQgxqFY019l/4t2rX51Si8pE1bsTTAsSzYgoOtshibEbbmysw+1VHCL2xX6Wjwf9ytFmp/OWPxjw0U76xBPeXvOzi27kCAOWwGbHKRzsUecWJKfhFDIG6Yf33uDKNtjmNw+UVaZWTA8N3I4sbyPBj8sY0uJVRTy4BXbeMMrdiXKPiMmMQW8oTVSBKc3jNlaYcHr7uERdk5k3bvqX2Vnh2hRahGpzS3ZKQiSNswYtTQh57n9Hz3kdtcjSn8E3h4CLF60fX14oOQqfxJcSmMjDM9QWhiqoQIDAQABo4GSMIGPMBoGA1UdEQQTMBGCD2ZpeHR1cmUuaW52YWxpZDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUlqkQECg0sGpBDLwessvijYNrWrwwHwYDVR0jBBgwFoAUdxiibNw0GYOFHT/Zk108KRfDh7AwDQYJKoZIhvcNAQELBQADggEBAG0/7UEsDZm6MB7tdYslY11Ghn1H2eJYLvyhdH78p8uo/Xw+LmWHq4V+wFPjpVko39iz5NjVFWccleP1nrd+CqFj0iwvHMI7zObG+sCQqHSW0H/1iTQdRnDZsABocRvvpvxPLODRkqAQTUcoACa7h8nGxJZKVnA+R+3wl4163OPWwS8YvDVBKz9gt/SDDhzkj/WxEvDYhMmIR4FMxeP6ix5fl0LOi8gA/1xDrUq2WUhRxw1hmbfPDWWWR8Yci7sZ4DRkJkyoWfl/nEIQverArpRw0HkJv0w9m2OhaVKmHCFnVsgBvlFFqbKm/4rfaUXJH7fYLbpuxXyXToAMrDlg3ms=";
const FIXTURE_LEAF_KEY_DER: &str = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDJS7id4aYmtMbwUtE0dvd6gS32aLevzavgKDeG+oDnNK3BwLvPUhDKYzjhNCDGoVjTX2X/i3atfnVKLykTVuxNMCxLNiCg62yGJsRtubKzD7VUcIvbFfpaPB/3K0Wan85Y/GPDRTvrEE95e87OLbuQIA5bAZscpHOxR5xYkp+EUMgbph/fe4Mo22OY3D5RVplZMDw3cjixvI8GPyxjS4lVFPLgFdt4wyt2Jco+IyYxBbyhNVIEpzeM2Vphwevu4RF2TmTdu+pfZWeHaFFqEanNLdkpCJI2zBi1NCHnuf0fPeR21yNKfwTeHgIsXrR9fXig5Cp/ElxKYyMMz1BaGKqhAgMBAAECggEAC9h2g6b13Lj+bIHJIR/fmiBMNMAOkCxHoSQouVsYNxLi50AY5T9AcPKEFD+ZrqqrxBuM8Gvz9st2akBKd+KBexzavG3R33pfK2lQXZ8kCJTD8FVDq6e4UPNRE73ihZICJfsrQUBboW53KNBb+AbZruZuBdW7O6UjUENFLHKra7Es5F5/i7avYNSAodocQmGQaurzrJnPUNv+jsk1R9TCLz6IaBM3NoTMa7ra+hOrflzZi1iLaAhpatCU7y9saxIwhlw6Xf++QNV3M5vRr/7+gfcnijGV53cVz1lCGQTpTLvJu8yNQGYcL8K/R7l+6KwyqP7GaHqURdpGUuhScyLB+QKBgQD+D+ZxNcZp7cKOM/UYLhC6yGc2v9DymCx0RrDuq1Tc/YKSaZqM1gZQAENjYLoKPhM1n9kuSzakQAzNto6mzxS9xnqOhZJlaarT7wmNHI6s4ZIVvQMPxL/ozQcqEzk3/r8LDSjdWjyJZqsBqdx2kNy7nxsxl7WB35yNopueDJP0OQKBgQDK1MkjgFRaWzDmCCWL4ZXz6F+BYJjwwhAOWZRTtEKkrNJQn8tux+jLywfZ1Hsq/5QASstdvjbrhQW3/QfNIr6wGZ6JRXG3CbYG9zusiwABOrjHcI9n8LESVMBEa/JdhA8Amp/08UXaieHWCYfiMY5BJaJYkHkbEzXB2huTvOn5qQKBgFxQYLZACOFSj//lpyfrDQ8hZEeDeSO84WI6kW2XeZV20+vpTUvhNJf7EIFakx7HoWk5tMtabvdNgpl4vOqlke7G4J9Kr4AD3ht13q2Uc88jg1Y8wJEJN4YagYDrTT4oZThZxsBvWlG+qWJIWyAF0P6neFUTv9L58kOQkyThgx0ZAoGANy6pAlWZnXON3Cd/P41CJLeltCc5tNa3U5AfgJ5cOz0hgvnWeO8+cKNuIV9jmxEpjOLMbVagznbEVYgrpS28v2BY93PDOk8UDNUakRjICY2WU/xVp6ueISSZooPTzoltI3bt6c/yd0BoBrlVFL7yutqoTnwP1sPlLjZOpmURKvECgYAXwVj+25V1iZYzHpl3L70ZJ4m/HulqR0nYqNQpjCHptNakoy2D64qqJXDp4KG1pm8xe0ghgzq18nrc1GTMRHY3T/maI/Q4X/tjqsIZxuqrpqGPGbgoBTSjIsXfG5/XxZc1UA195hO5cFQIzh2/sApm9P86HlaLP5AoAkdpuAFXCg==";

fn source_id() -> SourceId {
    SourceId::new(Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap()).unwrap()
}

fn fixture_png() -> Vec<u8> {
    let pixels = vec![0x55_u8; 32 * 32 * 4];
    let mut png = Vec::new();
    PngEncoder::new_with_quality(&mut png, CompressionType::Best, FilterType::Paeth)
        .write_image(&pixels, 32, 32, image::ExtendedColorType::Rgba8)
        .unwrap();
    png
}

#[test]
fn parser_extracts_bounded_inert_candidates_without_evidence_leakage() {
    let mut images = vec![
        r#"<img src="https://SHOP.Example./products/shirt.png#tracking" alt="Shirt">"#.to_owned(),
        r#"<img src="https://shop.example/products/shirt.png">"#.to_owned(),
        r#"<img src="http://shop.example/insecure.png">"#.to_owned(),
        r#"<img src="https://127.0.0.1/private.png">"#.to_owned(),
        r#"<img src="/relative.png">"#.to_owned(),
        r#"<img hidden src="https://shop.example/hidden.png">"#.to_owned(),
    ];
    for index in 0..MAX_RECEIPT_IMAGE_CANDIDATES {
        images.push(format!(
            r#"<img src="https://cdn.example/image-{index}.png">"#
        ));
    }
    let html = images.join("");
    let eml = format!(
        "From: receipts@example.invalid\r\nContent-Type: text/html; charset=utf-8\r\n\r\n\
         <html><body><p>Order: Shirt</p>{html}</body></html>"
    );

    let bundle = parse_receipt_bundle_v1(source_id(), eml.as_bytes()).unwrap();
    assert_eq!(bundle.image_candidates.len(), MAX_RECEIPT_IMAGE_CANDIDATES);
    assert!(bundle.image_candidate_overflow > 0);
    assert!(bundle
        .evidence
        .fragments
        .iter()
        .all(|fragment| !fragment.text.contains("https://")
            && !fragment.text.contains("http://")
            && !fragment.text.contains("shop.example")));

    let shirt = bundle
        .image_candidates
        .iter()
        .find(|candidate| candidate.display_host == "shop.example")
        .unwrap();
    assert_eq!(shirt.occurrence_count, 2);
    assert_eq!(
        shirt.normalized_url,
        "https://shop.example:443/products/shirt.png"
    );
    assert_eq!(
        shirt.eligibility,
        ReceiptImageCandidateEligibilityV1::Eligible
    );
    assert!(bundle.image_candidates.iter().any(|candidate| {
        candidate.normalized_url.starts_with("http://")
            && candidate.eligibility == ReceiptImageCandidateEligibilityV1::Blocked
    }));
    assert!(bundle.image_candidates.iter().any(|candidate| {
        candidate.display_host == "127.0.0.1"
            && candidate.eligibility == ReceiptImageCandidateEligibilityV1::Blocked
    }));
    assert!(bundle
        .image_candidates
        .iter()
        .all(|candidate| candidate.display_host != "hidden.png"));
}

#[test]
fn production_policy_rejects_mixed_and_metadata_answers() {
    let policy = SealedProductionAddressPolicy::new();
    assert_eq!(
        policy.validate(&[
            "8.8.8.8:443".parse().unwrap(),
            "169.254.169.254:443".parse().unwrap()
        ]),
        Err(ReceiptImageFailureCodeV1::AddressRejected)
    );
    assert_eq!(
        policy.validate(&["168.63.129.16:443".parse().unwrap()]),
        Err(ReceiptImageFailureCodeV1::AddressRejected)
    );
    assert!(policy
        .validate(&[
            "1.1.1.1:443".parse().unwrap(),
            "[2606:4700:4700::1111]:443".parse().unwrap()
        ])
        .is_ok());
    assert_eq!(
        policy.validate(&["1.1.1.1:8443".parse().unwrap()]),
        Err(ReceiptImageFailureCodeV1::AddressRejected)
    );
}

#[derive(Clone)]
struct FixtureResolver {
    calls: Arc<AtomicUsize>,
    address: SocketAddr,
}

impl ReceiptImageResolver for FixtureResolver {
    async fn lookup_ip(&self, _host: &str) -> Result<Vec<SocketAddr>, ReceiptImageFailureCodeV1> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![self.address])
    }
}

#[derive(Clone)]
struct FixtureAddressPolicy {
    permitted: SocketAddr,
}

impl ReceiptImageAddressPolicy for FixtureAddressPolicy {
    fn validate(&self, addresses: &[SocketAddr]) -> Result<(), ReceiptImageFailureCodeV1> {
        if addresses == [self.permitted] {
            Ok(())
        } else {
            Err(ReceiptImageFailureCodeV1::AddressRejected)
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn host_mismatch_fails_before_dns_and_loopback_is_test_policy_only() {
    let calls = Arc::new(AtomicUsize::new(0));
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let fixture_socket = SocketAddr::new(loopback, 443);
    let downloader = ReqwestReceiptImageDownloader::new(
        FixtureResolver {
            calls: Arc::clone(&calls),
            address: fixture_socket,
        },
        SystemClock,
        FixtureAddressPolicy {
            permitted: fixture_socket,
        },
    );

    let mismatch = downloader
        .download_with_deadline(ReceiptImageDownloadRequestV1 {
            normalized_url: "https://fixture.invalid:443/image.png".to_owned(),
            approved_display_host: "different.invalid".to_owned(),
            deadline: Instant::now() + Duration::from_secs(1),
        })
        .await;
    assert_eq!(mismatch, Err(ReceiptImageFailureCodeV1::HostMismatch));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let transport = downloader
        .download_with_deadline(ReceiptImageDownloadRequestV1 {
            normalized_url: "https://fixture.invalid:443/image.png".to_owned(),
            approved_display_host: "fixture.invalid".to_owned(),
            deadline: Instant::now() + Duration::from_secs(2),
        })
        .await;
    assert!(matches!(
        transport,
        Err(ReceiptImageFailureCodeV1::TransportFailed)
            | Err(ReceiptImageFailureCodeV1::DeadlineExceeded)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!SealedProductionAddressPolicy::permits(loopback));
}

#[tokio::test(flavor = "current_thread")]
async fn real_reqwest_rustls_download_uses_the_pinned_fixture_socket() {
    let root_certificate_der = STANDARD.decode(FIXTURE_CERT_DER).unwrap();
    let _test_only_ca_key = STANDARD.decode(FIXTURE_KEY_DER).unwrap();
    let leaf_certificate_der = STANDARD.decode(FIXTURE_LEAF_CERT_DER).unwrap();
    let private_key_der = STANDARD.decode(FIXTURE_LEAF_KEY_DER).unwrap();
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf_certificate_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_der)),
        )
        .unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let fixture_socket = listener.local_addr().unwrap();
    let expected_png = fixture_png();
    let response_png = expected_png.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = TlsAcceptor::from(Arc::new(server_config))
            .accept(stream)
            .await
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1_024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.unwrap();
            assert!(read > 0);
            request.extend_from_slice(&buffer[..read]);
            assert!(request.len() <= 16 * 1024);
        }
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            response_png.len()
        );
        stream.write_all(headers.as_bytes()).await.unwrap();
        stream.write_all(&response_png).await.unwrap();
        stream.shutdown().await.unwrap();
        String::from_utf8(request).unwrap()
    });

    let calls = Arc::new(AtomicUsize::new(0));
    let root = reqwest::Certificate::from_der(&root_certificate_der).unwrap();
    let downloader = ReqwestReceiptImageDownloader::new(
        FixtureResolver {
            calls: Arc::clone(&calls),
            address: fixture_socket,
        },
        SystemClock,
        FixtureAddressPolicy {
            permitted: fixture_socket,
        },
    )
    .with_additional_root_certificate(root);
    let downloaded = downloader
        .download_with_deadline(ReceiptImageDownloadRequestV1 {
            normalized_url: "https://fixture.invalid:443/image.png".to_owned(),
            approved_display_host: "fixture.invalid".to_owned(),
            deadline: Instant::now() + Duration::from_secs(3),
        })
        .await;
    if let Err(failure) = downloaded {
        let server_result = tokio::time::timeout(Duration::from_secs(1), server).await;
        panic!("download failed: {failure:?}; fixture: {server_result:?}");
    }
    let downloaded = downloaded.unwrap();
    let wire_request = server.await.unwrap().to_ascii_lowercase();

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(downloaded.source_bytes, expected_png);
    assert_eq!(downloaded.source_media_type, "image/png");
    assert_eq!((downloaded.width, downloaded.height), (32, 32));
    assert_eq!(downloaded.hops.len(), 1);
    assert_eq!(downloaded.hops[0].pinned_addresses, ["127.0.0.1"]);
    assert!(wire_request.starts_with("get /image.png http/1.1\r\n"));
    assert!(wire_request.contains("\r\nhost: fixture.invalid\r\n"));
    for forbidden in [
        "authorization:",
        "proxy-authorization:",
        "cookie:",
        "referer:",
        "if-none-match:",
        "if-modified-since:",
    ] {
        assert!(!wire_request.contains(forbidden));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cross_host_redirect_is_rejected_before_alternate_dns() {
    let root_certificate_der = STANDARD.decode(FIXTURE_CERT_DER).unwrap();
    let leaf_certificate_der = STANDARD.decode(FIXTURE_LEAF_CERT_DER).unwrap();
    let private_key_der = STANDARD.decode(FIXTURE_LEAF_KEY_DER).unwrap();
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf_certificate_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_der)),
        )
        .unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let fixture_socket = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = TlsAcceptor::from(Arc::new(server_config))
            .accept(stream)
            .await
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1_024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.unwrap();
            assert!(read > 0);
            request.extend_from_slice(&buffer[..read]);
        }
        stream
            .write_all(
                b"HTTP/1.1 302 Found\r\nLocation: https://other.invalid/image.png\r\n\
                  Content-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });

    let calls = Arc::new(AtomicUsize::new(0));
    let root = reqwest::Certificate::from_der(&root_certificate_der).unwrap();
    let downloader = ReqwestReceiptImageDownloader::new(
        FixtureResolver {
            calls: Arc::clone(&calls),
            address: fixture_socket,
        },
        SystemClock,
        FixtureAddressPolicy {
            permitted: fixture_socket,
        },
    )
    .with_additional_root_certificate(root);
    let result = downloader
        .download_with_deadline(ReceiptImageDownloadRequestV1 {
            normalized_url: "https://fixture.invalid:443/image.png".to_owned(),
            approved_display_host: "fixture.invalid".to_owned(),
            deadline: Instant::now() + Duration::from_secs(3),
        })
        .await;

    assert_eq!(result, Err(ReceiptImageFailureCodeV1::RedirectCrossHost));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    server.await.unwrap();
}
