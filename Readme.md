# Generate Key Pair by Mutual Remote Attestation

In this case, both server and client have sgx device, and they verify each other's quote.

**NOTE: If client doesn't have sgx device, use the code in ue-ra.**
## Requirements

To use this code sample, one needs to register at [Intel website](https://api.portal.trustedservices.intel.com/EPID-attestation) for dev IAS service access. Once the registration is finished, the following stuff should be ready:

1. An SPID assigned by Intel
2. IAS API Key assigned by Intel

Both of these information could be found in the new [Intel Trusted Services API Management Portal](https://api.portal.trustedservices.intel.com/developer). Please log into this portal and switch to "Manage subscriptions" page on the top right corner to see your SPID and API keys. Either primary key or secondary key works.

Save them to `bin/spid.txt` and `bin/key.txt` respectively. Size of these two files should be 32 or 33.

## Run

Start server

```bash
cd server
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
cd client
make
cd bin
# Receive Ecc public key from server (-g can be omitted)
./app -g
# or
# Send Ecc public key to server for verification
./app -v
# or
# Receive signature & message from server and verify sig
./app -s
```
