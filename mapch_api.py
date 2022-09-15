from flask import Flask, request, jsonify
import chamwithemp
import MAABE
from charm.toolbox.pairinggroup import PairingGroup, GT
from json import dumps
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction,SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor

app = Flask(__name__)

groupObj = PairingGroup('SS512')

maabe = MAABE.MaabeRW15(groupObj)
chamHash = chamwithemp.Chamwithemp()

public_parameters = maabe.setup()
print(public_parameters)

#################################

def convert_pairing_to_hex(obj_group, obj_to_convert):
    seralized_obj = obj_group.serialize(obj_to_convert)
    hexed_obj = seralized_obj.hex()
    return hexed_obj

def convert_hex_to_pairing(obj_group, hexed_obj):
    byte_obj1 = bytes.fromhex(hexed_obj)
    pairing_obj = obj_group.deserialize(byte_obj1)
    return pairing_obj

def convert_abe_master_sk_from_json(sk_json):
    return {"name" : sk_json["name"], "alpha" : convert_hex_to_pairing(groupObj, sk_json["alpha"]), "y" : convert_hex_to_pairing(groupObj, sk_json["y"])}

def convert_abe_master_pk_from_json(pk_json):
    return {"name" : pk_json["name"], "egga" : convert_hex_to_pairing(groupObj, pk_json["egga"]), "gy" : convert_hex_to_pairing(groupObj, pk_json["gy"]) },

def convert_cham_pk(pk_json):
    return {
        'secparam': int(pk_json["secparam"]), 
        'N': convert_hex_to_pairing(chamwithemp.group, pk_json["N"]), 
        'phi_N': convert_hex_to_pairing(chamwithemp.group, pk_json["phi_N"])
    }

def convert_cham_sk(sk_json):
    return {
        'p': convert_hex_to_pairing(chamwithemp.group, sk_json["p"]), 
        'q': convert_hex_to_pairing(chamwithemp.group, sk_json["q"])
    }

#################################

# @app.route("/", methods=["POST"])
# def root():
#     return {"m" : "a"}

@app.route("/create_abe_authority", methods=['POST'])
def maabe_auth_setup():
    request_data = request.json
    authority_name = request_data["authority_name"]
    (pk, sk) = maabe.authsetup(public_parameters, authority_name)
    # maabepk = {authority_name : pk1}
    # maabesk = {authority_name : sk1}
    return dumps({
        "pk" : {"name" : authority_name, "egga" : convert_pairing_to_hex(groupObj, pk["egga"]), "gy" : convert_pairing_to_hex(groupObj, pk["gy"]) },
        "sk" : {"name" : authority_name, "alpha" : convert_pairing_to_hex(groupObj, sk["alpha"]), "y" : convert_pairing_to_hex(groupObj, sk["y"]) }
    })

@app.route("/create_ch_keys", methods=['GET'])
def create_chamhash_keys():
    
    (pk, sk) = chamHash.keygen(1024)
    
    return dumps({
        "pk" : {
            'secparam': pk["secparam"], 
            'N': convert_pairing_to_hex(chamwithemp.group, pk["N"]), 
            'phi_N': convert_pairing_to_hex(chamwithemp.group, pk["phi_N"])
            },
        "sk" : {
            'p': convert_pairing_to_hex(chamwithemp.group, sk["p"]), 
            'q': convert_pairing_to_hex(chamwithemp.group, sk["q"])
        }
    })

# NOTE: test
@app.route("/create_abe_attribute_secret_key", methods=['POST'])
def create_multiple_attributes_key():
    request_data = request.json 
    json_sk = request_data["sk"]
    sk = convert_abe_master_sk_from_json(json_sk)
    gid = request_data["gid"] # e.g PATIENTA
    user_attribute = list(request_data["user_attribute"]) # e.g ['PATIENT@DOCTORA']
    user_sk_dict = maabe.multiple_attributes_keygen(public_parameters, sk, gid, user_attribute)

    json_user_sk = {}

    for attr, attr_key in user_sk_dict.items():
        json_user_sk[attr] = {"K": convert_pairing_to_hex(groupObj, attr_key["K"]), "KP": convert_pairing_to_hex(groupObj, attr_key["KP"])}

    return dumps(json_user_sk)

@app.route("/hash", methods=['POST'])
def hash():

    request_data = request.json 
    
    ## cham hash ##
    
    json_cham_pk = request_data["cham_pk"]
    json_cham_sk = request_data["cham_sk"]
    msg = request_data["message"]

    pk = convert_cham_pk(json_cham_pk)
    sk = convert_cham_sk(json_cham_sk)

    xi = chamHash.hash(pk, sk, msg)
    etd = [xi['p1'],xi['q1']]
    #if debug: print("Hash...")
    #if debug: print("hash result =>", xi)
 
    ## abe encypt##

    maabepk = convert_abe_master_pk_from_json(request_data["authority_abe_pk"])
    access_policy = request_data["access_policy"]

    rand_key = groupObj.random(GT)
    #if debug: print("msg =>", rand_key)
    #encrypt rand_key
    maabect = maabe.encrypt(public_parameters, maabepk, rand_key, access_policy)
    #rand_key->symkey AE  
    symcrypt = AuthenticatedCryptoAbstraction(extractor(rand_key))
    #symcrypt msg(etd=(p1,q1))
    etdtostr = [str(i) for i in etd]
    etdsumstr = etdtostr[0]+etdtostr[1]
    symct = symcrypt.encrypt(etdsumstr)

    ct = {'rkc':maabect,'ec':symct}

    #if debug: print("\n\nCiphertext...\n")
    #groupObj.debug(ct)
    #print("ciphertext:=>", ct)
    h = {'h': xi['h'], 'r': xi['r'], 'cipher':ct, 'N1': xi['N1'], 'e': xi['e']}
    print(h)

    return dumps({"status" : "done"})

# @app.route('/post_json', methods=['POST'])
# def process_json():
#     json = request.json
#     return json

# access_policy = '(PATIENT@DOCTORA)'
# user_sk = {'GID': gid, 'keys': MAPCH.merge_dicts(user_sk1)}

#################################

app.run()
