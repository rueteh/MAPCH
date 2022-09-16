import requests
import json

head = {"Content-Type": "application/json"}
body = {}

### create abe authority
print("CREATING ABE AUTHORITY ===\n")
body = { "authority_name" : "DOCTORA" }
x = requests.post("http://127.0.0.1:5000/create_abe_authority", headers=head, json=body)
maab_master_pk_sk = json.loads(x.text)
print(maab_master_pk_sk)

### create ch keys
print("CREATING CH KEYS ===\n")
body = {}

x = requests.get("http://127.0.0.1:5000/create_ch_keys", headers=head)
cham_hash_pk_sk = json.loads(x.text)
print(cham_hash_pk_sk)

### create abe attribute secret key
print("CREATING ABE SECRET KEY ===\n")
body = {
    "sk" : maab_master_pk_sk["sk"],
    "gid" : "Patient",
    "user_attribute" : ["PATIENT@DOCTORA"]
}

x = requests.post("http://127.0.0.1:5000/create_abe_attribute_secret_key", headers=head, json=body)
abe_secret_key = json.loads(x.text)
print(abe_secret_key)

### hash
print("CREATING HASH ===\n")
body = {
    "cham_pk" : cham_hash_pk_sk["pk"],
    "cham_sk" : cham_hash_pk_sk["sk"],
    "message" : "msg",
    "authority_abe_pk" : maab_master_pk_sk["pk"],
    "access_policy" : "(PATIENT@DOCTORA)"
}

x = requests.post("http://127.0.0.1:5000/hash", headers=head, json=body)
hash = json.loads(x.text)
print(hash)

### verify
print("VERIFYING HASH ===\n")
body = {
    "message" : "msg",
    "cham_pk" : cham_hash_pk_sk["pk"],
    "hash" : hash
}
x = requests.post("http://127.0.0.1:5000/hash_verify", headers=head, json=body)
hash_res = json.loads(x.text)
print(hash_res)
assert hash_res["is_hash_valid"] == "True"

### collision
print("ADAPTING HASH ===\n")
body = {
    "hash" : hash,
    "original_message" : "msg",
    "new_message" : "msg new",
    "cham_pk" : cham_hash_pk_sk["pk"],
    "gid" : "Patient",
    "abe_secret_key" : abe_secret_key
}

x = requests.post("http://127.0.0.1:5000/adapt", headers=head, json=body)
hash_modified = json.loads(x.text)
print(hash_modified)

### verify
print("VERIFYING HASH 2 ===\n")
body = {
    "message" : "msg new",
    "cham_pk" : cham_hash_pk_sk["pk"],
    "hash" : hash_modified
}
x = requests.post("http://127.0.0.1:5000/hash_verify", headers=head, json=body)
hash_res = json.loads(x.text)
print(hash_res)
assert hash_res["is_hash_valid"] == "True"
