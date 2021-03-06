# Generate Key Pair by Untrusted-Enclave Remote Attestation

In this case, client doesn't need to have sgx device, but needs to verify the quote from server's enclave.

## Requirements

To use this code sample, one needs to register at [Intel website](https://api.portal.trustedservices.intel.com/EPID-attestation) for dev IAS service access. Once the registration is finished, the following stuff should be ready:

1. An SPID assigned by Intel
2. IAS API Key assigned by Intel

Both of these information could be found in the new [Intel Trusted Services API Management Portal](https://api.portal.trustedservices.intel.com/developer). Please log into this portal and switch to "Manage subscriptions" page on the top right corner to see your SPID and API keys. Either primary key or secondary key works.

Save them to ue-ra-server's `bin/spid.txt` and `bin/key.txt` respectively. Size of these two files should be 32 or 33.

## Custom CA/client setup

To establish a TLS channel, we need a CA and generates a client cert for mutual authentication. We store them at `cert`.

1. Generate CA private key
openssl ecparam -genkey -name prime256v1 -out ca.key

2. Generate CA cert
openssl req -x509 -new -SHA256 -nodes -key ca.key -days 3650 -out ca.crt

3. Generate Client private key
openssl ecparam -genkey -name prime256v1 -out client.key

4. Export the keys to pkcs8 unencrypted format
openssl pkcs8 -topk8 -nocrypt -in client.key -out client.pkcs8

5. Generate Client CSR
openssl req -new -SHA256 -key client.key -nodes -out client.csr

6. Generate Client Cert
openssl x509 -req -extfile <(printf "subjectAltName=DNS:localhost,DNS:www.example.com") -days 3650 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt

7. Intel CA report signing pem. Download and uncompress:
https://software.intel.com/sites/default/files/managed/7b/de/RK_PUB.zip

## Embedding IAS credentials to ue-ra-server

`enclave/src/lib.rs` contains two funcs `load_spid` and `get_ias_api_key`. These two functions are configured to load spid/api key from `spid.txt` and `key.txt` from `bin` directory respectively. One can either adjust the file paths/names or copy the spid/key to `bin`. `spid.txt` and `key.txt` should only contain one line of 32 chars such as `DEADBEAFDEADBEAFDEADBEAFDEADBEAF`.

## Run

Start server

```bash
cd ue-ra-server
make
cd bin
# Generate Ecc key pair and send public key to client (-g can be omitted)
./app -g
# or
# Receive Ecc public key from client and verify it with the sealed private key
./app -v
# or
# Sign a message and send the signature to client
./app -s
```

Start client 

```bash
cd ue-ra-client
cargo build
cd target/debug
# Receive Ecc public key from server (-g can be omitted)
./ue-ra-client -g
# or
# Send Ecc public key to server for verification
./ue-ra-client -v
# or
# Receive signature & message from server and verify sig
./ue-ra-client -s
```
