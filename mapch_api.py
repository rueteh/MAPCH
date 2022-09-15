from flask import Flask, request, jsonify
import chamwithemp
import MAABE
from charm.toolbox.pairinggroup import PairingGroup, GT
from json import dumps

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

#################################

# @app.route("/", methods=["POST"])
# def root():
#     return {"m" : "a"}

@app.route("/create_abe_authority", methods=['POST'])
def maabe_auth_setup():
    request_data = request.json
    authority_name = request_data["authority_name"]
    (pk, sk) = maabe.authsetup(public_parameters, authority_name) # NOTE: egga is pairing element
    # maabepk = {authority_name : pk1}
    # maabesk = {authority_name : sk1}
    return dumps({
        "pk" : {authority_name : {"name" : authority_name, "egga" : convert_pairing_to_hex(groupObj, pk["egga"]), "gy" : convert_pairing_to_hex(groupObj, pk["gy"]) }},
        "sk" : {authority_name : {"name" : authority_name, "alpha" : convert_pairing_to_hex(groupObj, sk["alpha"]), "y" : convert_pairing_to_hex(groupObj, sk["y"]) }}
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

# @app.route('/post_json', methods=['POST'])
# def process_json():
#     json = request.json
#     return json

# #chamhash key init
# (pk, sk) = chamHash.keygen(1024)

# gid = "PATIENT_A"
# user_attr1 = ['PATIENT@DOCTORA']

# user_sk1 = maabe.multiple_attributes_keygen(public_parameters, sk1, gid, user_attr1)
# print("user_sk1=>",user_sk1)

# access_policy = '(PATIENT@DOCTORA)'
# user_sk = {'GID': gid, 'keys': MAPCH.merge_dicts(user_sk1)}

#################################

app.run()
