import chamwithemp
import MAABE
import re
from charm.toolbox.integergroup import integer
from charm.toolbox.pairinggroup import PairingGroup,GT
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction,SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor
import json

def merge_dicts(*dict_args):
    """
    Given any number of dicts, shallow copy and merge into a new dict,
    precedence goes to key value pairs in latter dicts.
    """
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result

def cut_text(text,lenth): 
    textArr = re.findall('.{'+str(lenth)+'}', text) 
    textArr.append(text[(len(textArr)*lenth):]) 
    return textArr

def hash(msg):
    xi = chamHash.hash(pk, sk, msg)
    etd = [xi['p1'],xi['q1']]
    #if debug: print("Hash...")
    #if debug: print("hash result =>", xi)
 
    # encrypt
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
    return h

def check(msg, h):
    checkresult = chamHash.hashcheck(pk, msg, h)
    return checkresult

def collision(msg1, msg2, h):
    #decrypt rand_key
    rec_key = maabe.decrypt(public_parameters, user_sk, h['cipher']['rkc'])
    #rec_key->symkey AE
    rec_symcrypt = AuthenticatedCryptoAbstraction(extractor(rec_key))
    #symdecrypt rec_etdsumstr
    rec_etdsumbytes = rec_symcrypt.decrypt(h['cipher']['ec'])
    rec_etdsumstr = str(rec_etdsumbytes, encoding="utf8")
    #print("etdsumstr type=>",type(rec_etdsumstr))
    #sumstr->etd str list
    rec_etdtolist = cut_text(rec_etdsumstr, 309)
   # print("rec_etdtolist=>",rec_etdtolist)
    #etd str list->etd integer list
    rec_etdint = {'p1': integer(int(rec_etdtolist[0])),'q1':integer(int(rec_etdtolist[1]))}
    #print("rec_etdint=>",rec_etdint)
    r1 = chamHash.collision(msg1, msg2, h, rec_etdint, pk)
    #if debug: print("new randomness =>", r1)
    new_h = {'h': h['h'], 'r': r1, 'cipher': h['cipher'], 'N1': h['N1'], 'e': h['e']}
    return new_h

groupObj = PairingGroup('SS512')

maabe = MAABE.MaabeRW15(groupObj)
chamHash = chamwithemp.Chamwithemp()

public_parameters = maabe.setup()
# print("pp is")
# print(public_parameters)

# obj1 = groupObj.serialize(public_parameters["g1"])
# print(obj1)
# print(type(obj1))

# decoded_obj1 = obj1.hex()
# print(decoded_obj1)
# print(type(decoded_obj1))
# print("nextt")

# encoded_obj1 = bytes.fromhex(decoded_obj1)
# replicated_obj1 = groupObj.deserialize(encoded_obj1)

# print(replicated_obj1)

# if replicated_obj1 == public_parameters["g1"]:
#     print("hiii")
# else:
#     print("bii")

# exit(0)

# (pk1, sk1) = maabe.authsetup(public_parameters, 'UT')
# (pk2, sk2) = maabe.authsetup(public_parameters, 'OU')
# maabepk = {'UT': pk1, 'OU': pk2}
# maabesk = {'UT': sk1, 'OU': sk2}

(pk1, sk1) = maabe.authsetup(public_parameters, 'DOCTORA')
maabepk = {'DOCTORA': pk1}
maabesk = {'DOCTORA': sk1}
print("maabepk ==>")
print(maabepk)

#chamhash key init
(pk, sk) = chamHash.keygen(1024)

gid = "PATIENT_A"
user_attr1 = ['PATIENT@DOCTORA']

user_sk1 = maabe.multiple_attributes_keygen(public_parameters, sk1, gid, user_attr1)
print("user_sk1=>",user_sk1)

access_policy = '(PATIENT@DOCTORA)'
user_sk = {'GID': gid, 'keys': merge_dicts(user_sk1)}

def main():
    # hash
    msg = "test 1"
    h = hash(msg)
    print("h =>", h)

    # hashcheck
    print("CHECKING FIRST HASH")

    checkresult = check(msg, h)
    print("checkresult =>", checkresult)

    #collision
    msg1 = "test 2"
    new_h = collision(msg,msg1,h)
    print("new_h =>", new_h)

    checkresult2 = check(msg1, new_h)
    print("checkresult2 =>", checkresult2)
    if checkresult2: 
        print("collision generated correctly!!!")

if __name__ == '__main__':
    debug = True
    main()