// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![crate_name = "mra"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
extern crate sgx_tcrypto;
extern crate sgx_trts;
extern crate sgx_tse;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;
extern crate sgx_tseal;

extern crate rustls;
extern crate webpki;
extern crate itertools;
extern crate base64;
extern crate httparse;
extern crate yasna;
extern crate bit_vec;
extern crate num_bigint;
extern crate chrono;
extern crate webpki_roots;
#[macro_use]
extern crate serde_derive;
extern crate serde_cbor;
extern crate serde;
extern crate serde_json;

use std::backtrace::{self, PrintFormat};
use sgx_types::*;
use sgx_tse::*;
//use sgx_trts::trts::{rsgx_raw_is_outside_enclave, rsgx_lfence};
use sgx_tcrypto::*;
use sgx_rand::*;
use sgx_tseal::SgxSealedData;

use std::prelude::v1::*;
use std::sync::Arc;
use std::net::TcpStream;
use std::string::{String, ToString};
use std::ptr;
use std::str;
use std::io::{Write, Read};
use std::untrusted::fs;
use std::vec::Vec;
use itertools::Itertools;

mod cert;
mod hex;
mod structs;
use structs::*;

pub const DEV_HOSTNAME:&'static str = "api.trustedservices.intel.com";
pub const SIGRL_SUFFIX:&'static str = "/sgx/dev/attestation/v3/sigrl/";
pub const REPORT_SUFFIX:&'static str = "/sgx/dev/attestation/v3/report";
pub const CERTEXPIRYDAYS: i64 = 90i64;

const LOG_SIZE: size_t = 1024;

extern "C" {
    pub fn ocall_sgx_init_quote ( ret_val : *mut sgx_status_t,
                  ret_ti  : *mut sgx_target_info_t,
                  ret_gid : *mut sgx_epid_group_id_t) -> sgx_status_t;
    pub fn ocall_get_ias_socket ( ret_val : *mut sgx_status_t,
                  ret_fd  : *mut i32) -> sgx_status_t;
    pub fn ocall_get_quote (ret_val            : *mut sgx_status_t,
                p_sigrl            : *const u8,
                sigrl_len          : u32,
                p_report           : *const sgx_report_t,
                quote_type         : sgx_quote_sign_type_t,
                p_spid             : *const sgx_spid_t,
                p_nonce            : *const sgx_quote_nonce_t,
                p_qe_report        : *mut sgx_report_t,
                p_quote            : *mut u8,
                maxlen             : u32,
                p_quote_len        : *mut u32) -> sgx_status_t;
    pub fn ocall_store_file (ret_val: *mut sgx_status_t, sealed_log: &[u8; LOG_SIZE],
        file_name: *const u8, name_len: usize) -> sgx_status_t;
    pub fn ocall_load_file (ret_val: *mut sgx_status_t, sealed_log: &mut [u8; LOG_SIZE],
        file_name: *const u8, name_len: usize) -> sgx_status_t;
}

fn parse_response_attn_report(resp : &[u8]) -> (String, String, String){
    println!("parse_response_attn_report");
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut respp   = httparse::Response::new(&mut headers);
    let result = respp.parse(resp);
    println!("parse result {:?}", result);

    let msg : &'static str;

    match respp.code {
        Some(200) => msg = "OK Operation Successful",
        Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
        Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
        Some(500) => msg = "Internal error occurred",
        Some(503) => msg = "Service is currently not able to process the request (due to
            a temporary overloading or maintenance). This is a
            temporary state ??? the same request can be repeated after
            some time. ",
        _ => {println!("DBG:{}", respp.code.unwrap()); msg = "Unknown error occured"},
    }

    println!("{}", msg);
    let mut len_num : u32 = 0;

    let mut sig = String::new();
    let mut cert = String::new();
    let mut attn_report = String::new();

    for i in 0..respp.headers.len() {
        let h = respp.headers[i];
        //println!("{} : {}", h.name, str::from_utf8(h.value).unwrap());
        match h.name{
            "Content-Length" => {
                let len_str = String::from_utf8(h.value.to_vec()).unwrap();
                len_num = len_str.parse::<u32>().unwrap();
                println!("content length = {}", len_num);
            }
            "X-IASReport-Signature" => sig = str::from_utf8(h.value).unwrap().to_string(),
            "X-IASReport-Signing-Certificate" => cert = str::from_utf8(h.value).unwrap().to_string(),
            _ => (),
        }
    }

    // Remove %0A from cert, and only obtain the signing cert
    cert = cert.replace("%0A", "");
    cert = cert::percent_decode(cert);
    let v: Vec<&str> = cert.split("-----").collect();
    let sig_cert = v[2].to_string();

    if len_num != 0 {
        let header_len = result.unwrap().unwrap();
        let resp_body = &resp[header_len..];
        attn_report = str::from_utf8(resp_body).unwrap().to_string();
        println!("Attestation report: {}", attn_report);
    }

    // len_num == 0
    (attn_report, sig, sig_cert)
}

fn parse_response_sigrl(resp : &[u8]) -> Vec<u8> {
    println!("parse_response_sigrl");
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut respp   = httparse::Response::new(&mut headers);
    let result = respp.parse(resp);
    println!("parse result {:?}", result);
    println!("parse response{:?}", respp);

    let msg : &'static str;

    match respp.code {
        Some(200) => msg = "OK Operation Successful",
        Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
        Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
        Some(500) => msg = "Internal error occurred",
        Some(503) => msg = "Service is currently not able to process the request (due to
            a temporary overloading or maintenance). This is a
            temporary state ??? the same request can be repeated after
            some time. ",
        _ => msg = "Unknown error occured",
    }

    println!("{}", msg);
    let mut len_num : u32 = 0;

    for i in 0..respp.headers.len() {
        let h = respp.headers[i];
        if h.name == "content-length" {
            let len_str = String::from_utf8(h.value.to_vec()).unwrap();
            len_num = len_str.parse::<u32>().unwrap();
            println!("content length = {}", len_num);
        }
    }

    if len_num != 0 {
        let header_len = result.unwrap().unwrap();
        let resp_body = &resp[header_len..];
        println!("Base64-encoded SigRL: {:?}", resp_body);

        return base64::decode(str::from_utf8(resp_body).unwrap()).unwrap();
    }

    // len_num == 0
    Vec::new()
}

pub fn make_ias_client_config() -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::new();

    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    config
}

pub fn get_sigrl_from_intel(fd : c_int, gid : u32) -> Vec<u8> {
    println!("get_sigrl_from_intel fd = {:?}", fd);
    let config = make_ias_client_config();
    //let sigrl_arg = SigRLArg { group_id : gid };
    //let sigrl_req = sigrl_arg.to_httpreq();
    let ias_key = get_ias_api_key();

    let req = format!("GET {}{:08x} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key: {}\r\nConnection: Close\r\n\r\n",
                        SIGRL_SUFFIX,
                        gid,
                        DEV_HOSTNAME,
                        ias_key);
    println!("{}", req);

    let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::new(fd).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    let _result = tls.write(req.as_bytes());
    let mut plaintext = Vec::new();

    println!("write complete");

    match tls.read_to_end(&mut plaintext) {
        Ok(_) => (),
        Err(e) => {
            println!("get_sigrl_from_intel tls.read_to_end: {:?}", e);
            panic!("haha");
        }
    }
    println!("read_to_end complete");
    let resp_string = String::from_utf8(plaintext.clone()).unwrap();

    println!("{}", resp_string);

    parse_response_sigrl(&plaintext)
}

// TODO: support pse
pub fn get_report_from_intel(fd : c_int, quote : Vec<u8>) -> (String, String, String) {
    println!("get_report_from_intel fd = {:?}", fd);
    let config = make_ias_client_config();
    let encoded_quote = base64::encode(&quote[..]);
    let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", encoded_quote);

    let ias_key = get_ias_api_key();

    let req = format!("POST {} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key:{}\r\nContent-Length:{}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                           REPORT_SUFFIX,
                           DEV_HOSTNAME,
                           ias_key,
                           encoded_json.len(),
                           encoded_json);
    println!("{}", req);
    let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::new(fd).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    let _result = tls.write(req.as_bytes());
    let mut plaintext = Vec::new();

    println!("write complete");

    tls.read_to_end(&mut plaintext).unwrap();
    println!("read_to_end complete");
    let resp_string = String::from_utf8(plaintext.clone()).unwrap();

    println!("resp_string = {}", resp_string);

    let (attn_report, sig, cert) = parse_response_attn_report(&plaintext);

    (attn_report, sig, cert)
}

fn as_u32_le(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) <<  0) +
    ((array[1] as u32) <<  8) +
    ((array[2] as u32) << 16) +
    ((array[3] as u32) << 24)
}

#[allow(const_err)]
pub fn create_attestation_report(pub_k: &sgx_ec256_public_t, sign_type: sgx_quote_sign_type_t) -> Result<(String, String, String), sgx_status_t> {
    // Workflow:
    // (1) ocall to get the target_info structure (ti) and epid group id (eg)
    // (1.5) get sigrl
    // (2) call sgx_create_report with ti+data, produce an sgx_report_t
    // (3) ocall to sgx_get_quote to generate (*mut sgx-quote_t, uint32_t)

    // (1) get ti + eg
    let mut ti : sgx_target_info_t = sgx_target_info_t::default();
    let mut eg : sgx_epid_group_id_t = sgx_epid_group_id_t::default();
    let mut retval : sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let res = unsafe {
        ocall_sgx_init_quote(&mut retval as *mut sgx_status_t,
                             &mut ti as *mut sgx_target_info_t,
                             &mut eg as *mut sgx_epid_group_id_t)
    };

    println!("eg = {:?}", eg);

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if retval != sgx_status_t::SGX_SUCCESS {
        return Err(retval);
    }

    let eg_num = as_u32_le(&eg);

    // (1.5) get sigrl
    let mut ias_sock : i32 = 0;

    let res = unsafe {
        ocall_get_ias_socket(&mut retval as *mut sgx_status_t,
                             &mut ias_sock as *mut i32)
    };

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if retval != sgx_status_t::SGX_SUCCESS {
        return Err(retval);
    }

    //println!("Got ias_sock = {}", ias_sock);

    // Now sigrl_vec is the revocation list, a vec<u8>
    let sigrl_vec : Vec<u8> = get_sigrl_from_intel(ias_sock, eg_num);

    // (2) Generate the report
    // Fill ecc256 public key into report_data
    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
    let mut pub_k_gx = pub_k.gx.clone();
    pub_k_gx.reverse();
    let mut pub_k_gy = pub_k.gy.clone();
    pub_k_gy.reverse();
    report_data.d[..32].clone_from_slice(&pub_k_gx);
    report_data.d[32..].clone_from_slice(&pub_k_gy);

    let rep = match rsgx_create_report(&ti, &report_data) {
        Ok(r) =>{
            println!("Report creation => success {:?}", r.body.mr_signer.m);
            Some(r)
        },
        Err(e) =>{
            println!("Report creation => failed {:?}", e);
            None
        },
    };

    let mut quote_nonce = sgx_quote_nonce_t { rand : [0;16] };
    let mut os_rng = os::SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut quote_nonce.rand);
    println!("rand finished");
    let mut qe_report = sgx_report_t::default();
    const RET_QUOTE_BUF_LEN : u32 = 2048;
    let mut return_quote_buf : [u8; RET_QUOTE_BUF_LEN as usize] = [0;RET_QUOTE_BUF_LEN as usize];
    let mut quote_len : u32 = 0;

    // (3) Generate the quote
    // Args:
    //       1. sigrl: ptr + len
    //       2. report: ptr 432bytes
    //       3. linkable: u32, unlinkable=0, linkable=1
    //       4. spid: sgx_spid_t ptr 16bytes
    //       5. sgx_quote_nonce_t ptr 16bytes
    //       6. p_sig_rl + sigrl size ( same to sigrl)
    //       7. [out]p_qe_report need further check
    //       8. [out]p_quote
    //       9. quote_size
    let (p_sigrl, sigrl_len) =
        if sigrl_vec.len() == 0 {
            (ptr::null(), 0)
        } else {
            (sigrl_vec.as_ptr(), sigrl_vec.len() as u32)
        };
    let p_report = (&rep.unwrap()) as * const sgx_report_t;
    let quote_type = sign_type;

    let spid : sgx_spid_t = load_spid("spid.txt");

    let p_spid = &spid as *const sgx_spid_t;
    let p_nonce = &quote_nonce as * const sgx_quote_nonce_t;
    let p_qe_report = &mut qe_report as *mut sgx_report_t;
    let p_quote = return_quote_buf.as_mut_ptr();
    let maxlen = RET_QUOTE_BUF_LEN;
    let p_quote_len = &mut quote_len as *mut u32;

    let result = unsafe {
        ocall_get_quote(&mut retval as *mut sgx_status_t,
                p_sigrl,
                sigrl_len,
                p_report,
                quote_type,
                p_spid,
                p_nonce,
                p_qe_report,
                p_quote,
                maxlen,
                p_quote_len)
    };

    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }

    if retval != sgx_status_t::SGX_SUCCESS {
        println!("ocall_get_quote returned {}", retval);
        return Err(retval);
    }

    // Added 09-28-2018
    // Perform a check on qe_report to verify if the qe_report is valid
    match rsgx_verify_report(&qe_report) {
        Ok(()) => println!("rsgx_verify_report passed!"),
        Err(x) => {
            println!("rsgx_verify_report failed with {:?}", x);
            return Err(x);
        },
    }

    // Check if the qe_report is produced on the same platform
    if ti.mr_enclave.m != qe_report.body.mr_enclave.m ||
       ti.attributes.flags != qe_report.body.attributes.flags ||
       ti.attributes.xfrm  != qe_report.body.attributes.xfrm {
        println!("qe_report does not match current target_info!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    println!("qe_report check passed");

    // Debug
    // for i in 0..quote_len {
    //     print!("{:02X}", unsafe {*p_quote.offset(i as isize)});
    // }
    // println!("");

    
    // Check qe_report to defend against replay attack
    // The purpose of p_qe_report is for the ISV enclave to confirm the QUOTE
    // it received is not modified by the untrusted SW stack, and not a replay.
    // The implementation in QE is to generate a REPORT targeting the ISV
    // enclave (target info from p_report) , with the lower 32Bytes in
    // report.data = SHA256(p_nonce||p_quote). The ISV enclave can verify the
    // p_qe_report and report.data to confirm the QUOTE has not be modified and
    // is not a replay. It is optional.

    let mut rhs_vec : Vec<u8> = quote_nonce.rand.to_vec();
    rhs_vec.extend(&return_quote_buf[..quote_len as usize]);
    let rhs_hash = rsgx_sha256_slice(&rhs_vec[..]).unwrap();
    let lhs_hash = &qe_report.body.report_data.d[..32];

    println!("rhs hash = {:02X}", rhs_hash.iter().format(""));
    println!("report hs= {:02X}", lhs_hash.iter().format(""));

    if rhs_hash != lhs_hash {
        println!("Quote is tampered!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    let quote_vec : Vec<u8> = return_quote_buf[..quote_len as usize].to_vec();
    let res = unsafe {
        ocall_get_ias_socket(&mut retval as *mut sgx_status_t,
                             &mut ias_sock as *mut i32)
    };

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if retval != sgx_status_t::SGX_SUCCESS {
        return Err(retval);
    }

    let (attn_report, sig, cert) = get_report_from_intel(ias_sock, quote_vec);
    Ok((attn_report, sig, cert))
}

fn load_spid(filename: &str) -> sgx_spid_t {
    let mut spidfile = fs::File::open(filename).expect("cannot open spid file");
    let mut contents = String::new();
    spidfile.read_to_string(&mut contents).expect("cannot read the spid file");

    hex::decode_spid(&contents)
}

fn get_ias_api_key() -> String {
    let mut keyfile = fs::File::open("key.txt").expect("cannot open ias key file");
    let mut key = String::new();
    keyfile.read_to_string(&mut key).expect("cannot read the ias key file");

    key.trim_end().to_owned()
}

fn gen_ecc_key_pair(file_name: &str) -> [u8; SGX_ECP256_KEY_SIZE*2] {
    println!("[+] Generate and Store Ecc Key Pair");
    // Generate key pair
    let ecc_handle = SgxEccHandle::new();
    ecc_handle.open().unwrap();
    let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();


    // Store key pair (Seal)
    let priv_key: EccPrivateKey = prv_k.into();
    let pub_key: EccPublicKey = pub_k.into();
    println!("[.] private key: {:?}\n[.] public key: {:?}", priv_key, pub_key);
    let _ = ecc_handle.close();

    // Store public key
    let mut pub_encoded: [u8; SGX_ECP256_KEY_SIZE*2] = [0; SGX_ECP256_KEY_SIZE*2];
    pub_encoded[..SGX_ECP256_KEY_SIZE].copy_from_slice(&pub_key.gx);
    pub_encoded[SGX_ECP256_KEY_SIZE..].copy_from_slice(&pub_key.gy);
    println!("[.] pub_encoded: {:?}", pub_encoded);
    let mut pub_log: [u8; LOG_SIZE] = [0; LOG_SIZE];
    pub_log[..SGX_ECP256_KEY_SIZE*2].copy_from_slice(&pub_encoded);
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        ocall_store_file(
            &mut retval as *mut sgx_status_t,
            &pub_log,
            file_name.as_ptr() as *const u8,
            file_name.len()
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] Store Public Key (ocall_store_file) Failed {}!", result.as_str());
        }
    }

    // We only need to seal private key
    let priv_encoded = serde_cbor::to_vec(&priv_key).unwrap();
    let priv_encoded = priv_encoded.as_slice();
    println!("[.] priv_encoded: {:?}", priv_encoded);
    let aad: [u8; 0] = [0_u8; 0];
    let result = SgxSealedData::<[u8]>::seal_data(&aad, priv_encoded);
    let sealed_priv = match result {
        Ok(x) => x,
        Err(ret) => {
            panic!("[-] Err seal data: {}", ret.as_str());
        },
    };
    let sealed_priv_log: [u8; LOG_SIZE] = [0; LOG_SIZE];
    let sealed_priv_log_size = sealed_priv_log.len() as u32;
    let opt = unsafe {
        sealed_priv.to_raw_sealed_data_t(sealed_priv_log.as_ptr() as *mut sgx_sealed_data_t, sealed_priv_log_size)
    };
    if opt.is_none() {
        println!("[-] Err to_raw_sealed_data_t")
    }
    println!("[.] sealed_priv: {:?}", sealed_priv_log);
    // Store sealed data to file
    let file_name = "ecc_priv_key_server_sealed".to_string();
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        ocall_store_file(
            &mut retval as *mut sgx_status_t,
            &sealed_priv_log,
            file_name.as_ptr() as *const u8,
            file_name.len())
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] Store Private Key (ocall_store_file) Failed {}!", result.as_str());
        }
    }

    pub_encoded
}

// Verify if a public key matches the private key
fn verify_pubkey(ecc_pub_key: &sgx_ec256_public_t, priv_file_name: &str) -> bool {
    println!("[+] Receive and Verify Public Key from Client");

    let ecc_priv_key = load_priv_key(&priv_file_name);
    
    // Validate key pair
    let ecc_handle = SgxEccHandle::new();
    ecc_handle.open().unwrap();
    let data = 12;
    let signature = ecc_handle.ecdsa_sign_msg(&data, &ecc_priv_key).unwrap();
    ecc_handle.ecdsa_verify_msg(&data, &ecc_pub_key, &signature).unwrap()
}

// Load and unseal private key
fn load_priv_key(file_name: &str) -> sgx_ec256_private_t {
    println!("[+] Load and Unseal Private Key");
    let mut ret_val = sgx_status_t::SGX_SUCCESS;
    let mut sealed_log: [u8; LOG_SIZE] = [0; LOG_SIZE];
    let sealed_log_size = sealed_log.len() as u32;
    let result = unsafe {
        ocall_load_file(
            &mut ret_val as *mut sgx_status_t, 
            &mut sealed_log,
            file_name.as_ptr() as *const u8, 
            file_name.len())
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            panic!("[-] ocall_load_file Failed {}", result.as_str());
        }
    }
    match ret_val {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            panic!("[-] ocall_load_file Failed {}", result.as_str());
        }
    }

    // Unseal private key
    let opt = unsafe {
        SgxSealedData::<[u8]>::from_raw_sealed_data_t(
            sealed_log.as_ptr() as *mut sgx_sealed_data_t, 
            sealed_log_size)
    };
    let sealed_data = match opt {
        Some(x) => x,
        None => {
            panic!("[-] unwrap sealed data fail");
        },
    };
    let result = sealed_data.unseal_data();
    let unsealed_data = match result {
        Ok(x) => x,
        Err(_ret) => {
            panic!("[-] unseal data fail");
        },
    };
    let priv_key_slice = unsealed_data.get_decrypt_txt();
    println!("[.] Unsealed Private Key from File: {:?}", priv_key_slice);

    // Deserialize private key
    let p: EccPrivateKey = serde_cbor::from_slice(priv_key_slice).unwrap();
    println!("[.] Deserialized Private Key: {:?}", &p);
    let ecc_priv_key = sgx_ec256_private_t {
        r: p.r,
    };
    ecc_priv_key
}

#[no_mangle]
pub extern "C" fn run_server(socket_fd : c_int, sign_type: sgx_quote_sign_type_t, op: u8) -> sgx_status_t {
    let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Short);

    // Generate Keypair
    let ecc_handle = SgxEccHandle::new();
    ecc_handle.open().unwrap();
    let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

    // Generate quote
    let (attn_report, sig, cert) = match create_attestation_report(&pub_k, sign_type) {
        Ok(r) => r,
        Err(e) => {
            println!("Error in create_attestation_report: {:?}", e);
            return e;
        }
    };

    let payload = attn_report + "|" + &sig + "|" + &cert;
    // Insert quote into cert
    let (key_der, cert_der) = match cert::gen_ecc_cert(payload, &prv_k, &pub_k, &ecc_handle) {
        Ok(r) => r,
        Err(e) => {
            println!("Error in gen_ecc_cert: {:?}", e);
            return e;
        }
    };
    ecc_handle.close().unwrap();

    let mut cfg = rustls::ServerConfig::new(Arc::new(ClientAuth::new(true)));
    let mut certs = Vec::new();
    certs.push(rustls::Certificate(cert_der));
    let privkey = rustls::PrivateKey(key_der);

    cfg.set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![]).unwrap();

    let mut sess = rustls::ServerSession::new(&Arc::new(cfg));
    let mut conn = TcpStream::new(socket_fd).unwrap();

    // Connect to Client
    let mut tls = rustls::Stream::new(&mut sess, &mut conn);
    // init connection
    let mut buf = [0u8; 32];
    match tls.read(&mut buf) {
        Ok(_) => {},
        Err(e) => {
            println!("Error in init connection: {:?}", e);
        }
    }

    match op {
        // Generate mode
        0 => {
            // Generate and store key pair
            let file_name = "ecc_pub_key_server".to_string();
            let pub_encoded = gen_ecc_key_pair(&file_name);
            // Communicate with client, send public key
            tls.write(&pub_encoded).unwrap();
        },
        // Verify mode
        1 => {
            // Get public key from client
            let mut pub_key_slice = Vec::new();
            match tls.read_to_end(&mut pub_key_slice) {
                Ok(_) => println!("[+] Get Public Key from Client"),
                Err(e) => {
                    println!("Error in read_to_end: {:?}", e);
                    panic!("");
                }
            };
            let pub_key_slice = pub_key_slice.as_slice();
            let k: EccPublicKey = serde_cbor::from_slice(pub_key_slice).unwrap();
            let pub_key = sgx_ec256_public_t {
                gx: k.gx,
                gy: k.gy,
            };

            // Verify public key
            let priv_file_name = "ecc_priv_key_server_sealed".to_string();
            let verify_sig = verify_pubkey(&pub_key, &priv_file_name);
            if verify_sig {
                println!("[+] Valid Ecc Key Pair.");
            } else {
                println!("[-] Invalid Ecc Key Pair!")
            }
        },
        // Sign mode
        2 => {
            // Send message
            let message = "Test Sign Mode1254adfasdfadsfda234afdsxxxaeee23".as_bytes();
            println!("Send Message: {:?}", message);

            // Load private key
            let file_name = "ecc_priv_key_server_sealed".to_string();
            let priv_key = load_priv_key(&file_name);

            // Sign message
            let ecc_handle = SgxEccHandle::new();
            ecc_handle.open().unwrap();
            let sig = ecc_handle.ecdsa_sign_slice(&message, &priv_key).unwrap();
            ecc_handle.close().unwrap();

            // Send signature
            let ecc_sig: EccSignature = sig.into();
            let sig_encoded = serde_cbor::to_vec(&ecc_sig).unwrap();
            let sig_encoded = sig_encoded.as_slice();
            // println!("Signature size: {}", sig_encoded.len());

            tls.write_all(&sig_encoded).unwrap();
            tls.write_all(message).unwrap();
        },
        // Other mode is invalid
        _ => { panic!("[-] Invalid Mode!") }
    }

    sgx_status_t::SGX_SUCCESS
}


// // Load public key
// let file_name = "ecc_pub_key_server".to_string();
// let mut ret_val = sgx_status_t::SGX_SUCCESS;
// let mut log: [u8; LOG_SIZE] = [0; LOG_SIZE];
// let result = unsafe {
//     ocall_load_file(
//         &mut ret_val as *mut sgx_status_t, 
//         &mut log,
//         file_name.as_ptr() as *const u8,
//         file_name.len())
// };
// match result {
//     sgx_status_t::SGX_SUCCESS => {},
//     _ => {
//         panic!("[-] ocall_load_file Failed {}", result.as_str());
//     }
// }
// match ret_val {
//     sgx_status_t::SGX_SUCCESS => {},
//     _ => {
//         panic!("[-] ocall_load_file Failed {}", result.as_str());
//     }
// }
// let mut pub_key_slice: [u8; SGX_ECP256_KEY_SIZE*2] = [0; SGX_ECP256_KEY_SIZE*2];
// pub_key_slice.copy_from_slice(&log[..SGX_ECP256_KEY_SIZE*2]);
// // println!("[.] Public Key from File: {:?}", pub_key_slice);

// // Deserialize public key
// let mut gx: [u8; SGX_ECP256_KEY_SIZE] = [0; SGX_ECP256_KEY_SIZE];
// let mut gy: [u8; SGX_ECP256_KEY_SIZE] = [0; SGX_ECP256_KEY_SIZE];
// gx.copy_from_slice(&pub_key_slice[..SGX_ECP256_KEY_SIZE]);
// gy.copy_from_slice(&pub_key_slice[SGX_ECP256_KEY_SIZE..]);
// let p = EccPublicKey {
//     gx,
//     gy,
// };
// // println!("[.] Deserialized Public Key: {:?}", &p);
// let ecc_pub_key = sgx_ec256_public_t {
//     gx: p.gx,
//     gy: p.gy,
// };