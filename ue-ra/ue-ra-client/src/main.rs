extern crate chrono;
extern crate webpki;
extern crate rustls;
extern crate base64;
extern crate itertools;
extern crate num_bigint;
extern crate bit_vec;
extern crate hex;
extern crate sgx_types;
extern crate sgx_ucrypto as crypto;
#[macro_use]
extern crate serde_derive;
extern crate serde_cbor;
extern crate serde;
extern crate serde_json;

use sgx_types::*;
use crypto::*;

use std::io::{self, Write, Read, BufReader};
use std::sync::Arc;
use std::{str, fs, env};
use std::net::TcpStream;

mod cert;
mod pib;

const SERVERADDR: &str = "localhost:3443";
const LOG_SIZE: size_t = 1024;
const SIG_SIZE: size_t = 87;

struct ServerAuth {
    outdated_ok: bool
}

impl ServerAuth {
    fn new(outdated_ok: bool) -> ServerAuth {
        ServerAuth{ outdated_ok }
    }
}

impl rustls::ServerCertVerifier for ServerAuth {
    fn verify_server_cert(&self,
              _roots: &rustls::RootCertStore,
              _certs: &[rustls::Certificate],
              _hostname: webpki::DNSNameRef,
              _ocsp: &[u8]) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        println!("--received-server cert: {:?}", _certs);
        // This call will automatically verify cert is properly signed
        match cert::verify_mra_cert(&_certs[0].0) {
            Ok(()) => {
                Ok(rustls::ServerCertVerified::assertion())
            }
            Err(sgx_status_t::SGX_ERROR_UPDATE_NEEDED) => {
                if self.outdated_ok {
                    println!("outdated_ok is set, overriding outdated error");
                    Ok(rustls::ServerCertVerified::assertion())
                } else {
                    Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid))
                }
            }
            Err(_) => {
                Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid))
            }
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct EccPrivateKey {
    pub r: [u8; SGX_ECP256_KEY_SIZE]
}

impl From<sgx_ec256_private_t> for EccPrivateKey {
    fn from(key: sgx_ec256_private_t) -> Self {
        EccPrivateKey { r: key.r }
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct EccPublicKey {
    pub gx: [u8; SGX_ECP256_KEY_SIZE],
    pub gy: [u8; SGX_ECP256_KEY_SIZE]
}

impl From<sgx_ec256_public_t> for EccPublicKey {
    fn from(key: sgx_ec256_public_t) -> Self {
        EccPublicKey {
            gx: key.gx,
            gy: key.gy
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct EccSignature {
    pub x: [u32; SGX_NISTP_ECP256_KEY_SIZE],
    pub y: [u32; SGX_NISTP_ECP256_KEY_SIZE],
}

impl From<sgx_ec256_signature_t> for EccSignature {
    fn from(sig: sgx_ec256_signature_t) -> Self {
        EccSignature {
            x: sig.x,
            y: sig.y,
        }
    }
}

fn make_config() -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::new();

    let client_cert = include_bytes!("../../cert/client.crt");
    let mut cc_reader = BufReader::new(&client_cert[..]);

    let client_pkcs8_key = include_bytes!("../../cert/client.pkcs8");
    let mut client_key_reader = BufReader::new(&client_pkcs8_key[..]);

    let certs = rustls::internal::pemfile::certs(&mut cc_reader).unwrap();
    let privk = rustls::internal::pemfile::pkcs8_private_keys(&mut client_key_reader);

    config.set_single_client_cert(certs, privk.unwrap()[0].clone());

    config.dangerous().set_certificate_verifier(Arc::new(ServerAuth::new(true)));
    config.versions.clear();
    config.versions.push(rustls::ProtocolVersion::TLSv1_2);

    config
}

fn store_pubkey(pub_key_slice: &[u8], file_name: &str) {
    // Store public key
    println!("Save file name: {}", file_name);
    fs::create_dir_all("storage").expect("Cannot create directory");
    let mut file = fs::File::create(format!("./storage/{}", file_name)).expect("create file failed");
    file.write_all(pub_key_slice).expect("write file failed");
}

fn load_pubkey(file_name: &str) -> sgx_ec256_public_t {
    println!("[+] Load Public Key from File");
    // Load public key
    let mut log: [u8; LOG_SIZE] = [0; LOG_SIZE];
    let file_name = format!("./storage/{}", file_name);

    let mut file = match fs::File::open(file_name){
        Ok(f) => f,
        Err(e) => {
            panic!("Cannot open file: {:?}", e);
        }
    };
    let _ = file.read(&mut log);

    let mut pub_key_slice: [u8; SGX_ECP256_KEY_SIZE*2] = [0; SGX_ECP256_KEY_SIZE*2];
    pub_key_slice.copy_from_slice(&log[..SGX_ECP256_KEY_SIZE*2]);
    println!("[.] Public Key from File: {:?}", pub_key_slice);

    // Deserialize public key
    let mut gx: [u8; SGX_ECP256_KEY_SIZE] = [0; SGX_ECP256_KEY_SIZE];
    let mut gy: [u8; SGX_ECP256_KEY_SIZE] = [0; SGX_ECP256_KEY_SIZE];
    gx.copy_from_slice(&pub_key_slice[..SGX_ECP256_KEY_SIZE]);
    gy.copy_from_slice(&pub_key_slice[SGX_ECP256_KEY_SIZE..]);
    let ecc_pub_key = sgx_ec256_public_t {
        gx,
        gy,
    };
    ecc_pub_key
}

fn verify_sig(buf: &[u8]) -> bool {
    println!("[+] Verify Signature");
    let sig_slice = &buf[..SIG_SIZE];
    let sig: EccSignature = serde_cbor::from_slice(&sig_slice).unwrap();
    let signature = sgx_ec256_signature_t {
        x: sig.x,
        y: sig.y,
    };
    let msg = &buf[SIG_SIZE..];

    // Load public key
    let file_name = "ecc_pub_key_server".to_string();
    let ecc_pub_key = load_pubkey(&file_name);

    // Verify signature
    let ecc_handle = SgxEccHandle::new();
    ecc_handle.open().unwrap();
    let verify = ecc_handle.ecdsa_verify_slice(&msg, &ecc_pub_key, &signature).unwrap();
    ecc_handle.close().unwrap();
    verify
}

fn main() {
    let mut args: Vec<_> = env::args().collect();
    args.remove(0);
    // In default, operation is store
    let mut op: u8 = 0;
    while !args.is_empty() {
        match args.remove(0).as_ref() {
            "--generate" | "-g" => op = 0,
            "--verify" | "-v" => op = 1,
            "--sign" | "-s" => op = 2,
            _ => {
                panic!("Only --generate(-g) or --verify(-v) or --sign(-s) is accepted [in default generate mode is on]");
            }
        }
    }
    println!("Starting ue-ra-client");
    println!("Connecting to {}", SERVERADDR);

    let client_config = make_config();
    let dns_name = webpki::DNSNameRef::try_from_ascii_str("localhost").unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(client_config), dns_name);

    let mut conn = TcpStream::connect(SERVERADDR).unwrap();

    let mut tls = rustls::Stream::new(&mut sess, &mut conn);

    // init connection
    tls.write_all("init".as_bytes()).unwrap();

    match op {
        // Generate mode
        0 => {
            // Get server's public key
            let mut pub_key_slice = Vec::new();
            match tls.read_to_end(&mut pub_key_slice) {
                Ok(_) => {
                    println!("[+] Get Public Key from Server");
                }
                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                    println!("[-] EOF (tls)");
                }
                Err(e) => println!("[-] Error in read_to_end: {:?}", e),
            }
            
            // Store public key
            let pub_key_slice = pub_key_slice.as_slice();
            let file_name = "ecc_pub_key_server".to_string();
            store_pubkey(pub_key_slice, &file_name)
        },
        // Verify mode
        1 => {
            // Load public key
            let file_name = "ecc_pub_key_server".to_string();
            let pub_key = load_pubkey(&file_name);
            let pub_key: EccPublicKey = pub_key.into();
            println!("[.] Deserialized Public Key: {:?}", &pub_key);
            let pub_key_slice = serde_cbor::to_vec(&pub_key).unwrap();
            let pub_key_slice = pub_key_slice.as_slice();

            // Send public key to server to verify
            tls.write(pub_key_slice).unwrap();
        },
        // Sign mode
        2 => {
            // Receive message & signature from server
            let mut buf = Vec::new();
            match tls.read_to_end(&mut buf) {
                Ok(_len) => {
                    println!("[+] Get Buf from Server: {}", _len);
                }
                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                    println!("[-] EOF (tls)");
                }
                Err(e) => println!("[-] Error in read_to_end: {:?}", e),
            }
            let buf = buf.as_slice();

            if verify_sig(buf) {
                println!("[+] Valid Signature.");
            } else {
                println!("[-] Invalid Signature!");
            }
        },
        // Other mode is invalid
        _ => { panic!("[-] Invalid Mode!") }
    }
}
