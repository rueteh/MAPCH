# from charm.toolbox.Hash import ChamHash
# from charm.toolbox.integergroup import IntegerGroupQ,gcd,randomPrime,isPrime,random,InitBenchmark,GetBenchmark,StartBenchmark,EndBenchmark
# from charm.toolbox.conversion import Conversion

from charm.toolbox.Hash import ChamHash
from charm.toolbox.integergroup import IntegerGroupQ,gcd,randomPrime,isPrime,random
from charm.toolbox.conversion import Conversion
import json

debug = False


class Chamwithemp(ChamHash):

    def __init__(self):
        #global group
        self.group = IntegerGroupQ(0)

    #generate pk sk
    def keygen(self, secparam):
        while True:
            p, q = randomPrime(secparam), randomPrime(secparam)
            print("p,q=>", p, q)
            if isPrime(p) and isPrime(q) and p != q:
                N = p * q
                phi_N = N - p - q + 1
                break
        pk = {'secparam': secparam, 'N': N, 'phi_N': phi_N}
        sk = {'p': p, 'q': q}
        return (pk, sk)

    #generate chameleon hash
    def hash(self, pk, sk, message, r=0):
        #generate ephemeral trapdoors(p1,q1)
        while True:
            p1, q1 = randomPrime(pk['secparam']), randomPrime(pk['secparam'])
            print("p1,q1=>",p1,q1)
            if isPrime(p1) and isPrime(q1) and p1 != q1:
                N1 = p1 * q1
                if not gcd(N1,pk['N']) == 1:
                    continue
                break

        if r == 0:
            r = random(N1 * pk['N'])
        print("r=>",r)
        print("(p1,q1,N1)=>", (p1,q1,N1))
        print("N*N1=>",N1 * pk['N'])
        phi_NN1 = pk['phi_N'] * (N1 - p1 - q1 + 1)
        print("phi_NN1=>", phi_NN1)

        #find e inverse mod N1 * N, so gcd(e,phi_NN1)==1
        while True:
            e = random(phi_NN1)
            if not gcd(e, phi_NN1) == 1:
                continue
            break

        M = Conversion.bytes2integer(message)
        print("M =>",M)

        #to set hash modular N * N1()
        self.group.q = N1 * pk['N']
        self.group.p = self.group.q * 2 + 1
        print("q=>",self.group.q)
        print("M hash=>", self.group.hash(M))

        h = (self.group.hash(M) * (r ** e)) % (N1 * pk['N'])
        xi = {'h': h, 'r': r, 'N1': N1, 'p1': p1, 'q1':q1, 'e':e}
        print("e=>",xi['e'])
        return xi

    def hashcheck(self, pk, message, xi):
        M = Conversion.bytes2integer(message)
        h1 = (self.group.hash(M) * (xi['r'] ** xi['e'])) % (pk['N'] * xi['N1'])
        if h1 == xi['h']:
            return True
        else:
            return False

    def collision(self, m, m1, xi, etd, pk):
        phi_NN1 = pk['phi_N'] * (xi['N1'] - etd['p1'] - etd['q1'] + 1)
        d = (xi['e'] ** -1) % (phi_NN1)
        print('d=>',d)
        if d == 1 / xi['e']:
            print('reverse')
        M1 = Conversion.bytes2integer(m1)
        M = Conversion.bytes2integer(m)
        h = (self.group.hash(M) * (xi['r'] ** xi['e'])) % (pk['N'] * xi['N1'])
        r1 = (((self.group.hash(M1) ** (-1)) * h) ** d) % (pk['N'] * xi['N1'])
        print("r1 =>", r1)
        return r1

def main():
        # test p and q primes for unit tests only
        #p = integer(
            #164960892556379843852747960442703555069442262500242170785496141408191025653791149960117681934982863436763270287998062485836533436731979391762052869620652382502450810563192532079839617163226459506619269739544815249458016088505187490329968102214003929285843634017082702266003694786919671197914296386150563930299)
        #q = integer(
            #82480446278189921926373980221351777534721131250121085392748070704095512826895574980058840967491431718381635143999031242918266718365989695881026434810326191251225405281596266039919808581613229753309634869772407624729008044252593745164984051107001964642921817008541351133001847393459835598957148193075281965149)

        #keygen
        chamHash = Chamwithemp()
        (pk, sk) = chamHash.keygen(1024)

        chamHash2 = Chamwithemp()
        (pk2, sk2) = chamHash2.keygen(1024)

        # hash
        msg = "Hello world this is the first message!"
        xi = chamHash.hash(pk, sk,msg)
        if debug: print("Hash...")
        if debug: print("hash result =>", xi)

        msg2 = "another hash"
        xi2 = chamHash2.hash(pk, sk, msg2)
        # if debug: print("Hash 2 ...")
        # if debug: print("hash 2 result =>", xi)

        # collision
        msg_modified = "Hello world this is the second message!"
        etd = {'p1':xi['p1'],'q1':xi['q1']}
        r1 = chamHash.collision(msg, msg_modified, xi, etd, pk)
        xi['r'] = r1
        if debug: print("new randomness =>", r1)

        etd2 = {'p1':xi2['p1'],'q1':xi2['q1']}
        r2 = chamHash2.collision(msg2, msg_modified, xi2, etd2, pk)
        xi2['r'] = r2
        if debug: print("new randomness =>", r2)

        if chamHash.hashcheck(pk,msg_modified,xi):
            print("success for 1")
        if chamHash2.hashcheck(pk,msg_modified,xi2):
            print("success for 2")

if __name__ == '__main__':
    debug = True
    main()

# print("pk secparam")
# print(type(pk["secparam"]))
# print("pk N")
# print(pk["N"])
# print(type(pk["N"]))

# seralized_obj = group.serialize(pk["N"])
# hexed_obj = seralized_obj.hex()
# byte_obj1 = bytes.fromhex(hexed_obj)
# pairing_obj = group.deserialize(byte_obj1)
# assert (pk["N"] == pairing_obj)

# print("pk phi_N")
# print(type(pk["phi_N"]))

# print("sk p")
# print(type(sk["p"]))
# print("sk q")
# print(type(sk["q"]))
# #print(json.dumps(sk["q"]))
# exit(0)