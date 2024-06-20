import os
import pickle
import string
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat

class MessengerServer:
    def __init__(self, server_signing_key, server_decryption_key):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key

    def decryptReport(self, report):
        pk, ct = report
        key = self.server_decryption_key.exchange(ec.ECDH(), pk)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(bytes(16), ct, None).decode()

    def signCert(self, cert):
        return self.server_signing_key.sign(cert, ec.ECDSA(hashes.SHA256()))

class MessengerClient:

    def __init__(self, name, server_signing_pk, server_encryption_pk):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.conns = {}
        self.certs = {}

    def generateCertificate(self):
        self.client_sk = ec.generate_private_key(ec.SECP256R1())
        self.client_pk = self.client_sk.public_key()
        cert = (self.name, self.client_pk.public_numbers())
        return pickle.dumps(cert)

    def receiveCertificate(self, certificate, signature):
        self.server_signing_pk.verify(signature, certificate, ec.ECDSA(hashes.SHA256()))
        name, pk = pickle.loads(certificate)
        self.certs[name] = pk.public_key()

    def sendMessage(self, name, message):
        if name not in self.conns:
            peerPk = self.certs[name]
            self.conns[name] = DoubleRatchet(peerPk)
        else:
            self.conns[name].pushS()
        key = self.conns[name].sndR.mk
        pk = self.conns[name].dhR.pk
        aad = pk.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        ct = self.encryptStr(key, message, aad)
        return pk, ct

    def receiveMessage(self, name, header, ciphertext):
        if name not in self.conns:
            self.conns[name] = DoubleRatchet(header, self.client_sk)
        else:
            self.conns[name].pushR(header)
        key = self.conns[name].rcvR.mk
        aad = header.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        try: 
            return self.decryptStr(key, ciphertext, aad)
        except: 
            return None

    def report(self, name, message):
        reportPt = str((name, message))
        sk = ec.generate_private_key(ec.SECP256R1())
        key = sk.exchange(ec.ECDH(), self.server_encryption_pk)
        reportCt = (sk.public_key(), self.encryptStr(key, reportPt))
        return reportPt, reportCt
        
    def encryptStr(self, key, data, aad=None):
        #print(self.name, key, data)
        aesgcm = AESGCM(key)
        return aesgcm.encrypt(bytes(16), data.encode(), aad)
        
    def decryptStr(self, key, ct, aad=None):
        #print(self.name, key)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(bytes(16), ct, aad).decode()

class DoubleRatchet:
    def __init__(self, peerPk, sk=None):
        self.sndR = None
        self.rcvR = None
        self.dhR = DhRatchet(peerPk, sk)
        self.rtR = RootRatchet(self.dhR.output)
        if sk is None:
            self.sndR = SymRatchet(self.rtR.rk)
        else:
            self.rcvR = SymRatchet(self.rtR.rk)
    
    def pushS(self): # empty peerPk used when sending a message
        if self.dhR.sk is None: # DH ratchet in receive state
            self.dhR.push()
            self.rtR.push(self.dhR.output)
            self.sndR = SymRatchet(self.rtR.rk)
        else:
            self.sndR.push()
    
    def pushR(self, peerPk):
        if self.dhR.sk is not None: # DH ratchet in send state
            self.dhR.push(peerPk)
            self.rtR.push(self.dhR.output)
            self.rcvR = SymRatchet(self.rtR.rk)
        else:
            self.rcvR.push()       

class DhRatchet:
    # only provide peerPk when initializing as a sender, add local sk when init as receiver
    def __init__(self, peerPk, sk=None):
        self.pk = peerPk
        self.sk = sk
        self.output = None
        if sk is None:
            self.push()
        else:
            self.push(self.pk)
    
    def push(self, peerPk=None):
        if peerPk is None:
            #going to send, generate the keys, give output and update pk
            self.sk = ec.generate_private_key(ec.SECP256R1())
            self.output = self.sk.exchange(ec.ECDH(), self.pk)
            self.pk = self.sk.public_key()
        else:
            #going to receive, update the pk and generate the keys
            self.pk = peerPk
            self.output = self.sk.exchange(ec.ECDH(), self.pk)
            self.sk = None

class RootRatchet:
    def __init__(self, k):
        self.rk = k
        self.push(self.rk)
    
    def push(self, dhInput):
        hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.rk,
                info=None,
            )
        self.rk = hkdf.derive(dhInput)

class SymRatchet:
    def __init__(self, k):
        self.ck = k
        self.mk = None
        self.push()
    
    def push(self):
        h = hmac.HMAC(self.ck, hashes.SHA256())
        h.update(b'\x00')
        self.ck = h.finalize()
        h = hmac.HMAC(self.ck, hashes.SHA256())
        h.update(b'\xFF')
        self.mk = h.finalize()

