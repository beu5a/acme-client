
import json
import time
from utils import b64_url
import challenge_http_server

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


import requests
from requests.adapters import HTTPAdapter


POLL_FREQ = 0.1
MAIL = "mailto:dummy@dummy.com"

class ACMEClient:
    def __init__(self, directory_url ,dns_server, challenge_type ,signing_alg="ES256"):

        self.dns_server = dns_server
        self.challenge_type = challenge_type 

        self.server_session = requests.Session()
        self.server_session.headers.update({"User-Agent": "acme_client", "Content-Type": "application/jose+json"})
        self.server_session.mount('https://', HTTPAdapter(max_retries=0))
        self.server_session.verify = "pebble.minica.pem" 


        self.directory_url = directory_url
        self.urls = {}
        
        self.alg = signing_alg #alg is the default signing algorithm
        self.sk , self.pk = self.generate_key()
        self.jwk = self.get_jwk(self.pk)
        self.kid = None #kid is the account url




    

    ######################################################################################################################################
    #Crypto functions
    def generate_key_ES256(self):
        sk = ECC.generate(curve='P-256')
        pk = sk.public_key()
        return sk, pk
    
    def generate_key_EdDSA(self):
        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key()
        return sk, pk
    
    def generate_key(self):
        if self.alg == "ES256":
            return self.generate_key_ES256()
        elif self.alg == "EdDSA":
            return self.generate_key_EdDSA()
        else:
            raise Exception("Unknown signing algorithm")


    def get_jwk_ES256(self, pk):
        return {
            "crv": "P-256",
            "kty": "EC",
            "x": b64_url(pk.pointQ.x.to_bytes()),
            "y": b64_url(pk.pointQ.y.to_bytes())
        }
    
    def get_jwk_EdDSA(self, pk):
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": pk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        }
    
    def get_jwk(self, pk):
        if self.alg == "ES256":
            return self.get_jwk_ES256(pk)
        elif self.alg == "EdDSA":
            return self.get_jwk_EdDSA(pk)
        else:
            raise Exception("Unknown signing algorithm")
    

    def sign_ES256(self, sk, msg):
        h = SHA256.new(msg)
        signer = DSS.new(sk, 'fips-186-3')
        return signer.sign(h) #return 64 bytes signature
    
    def sign_EdDSA(self, sk, msg):
        return sk.sign(msg) #return 64 bytes signature
    
    def sign(self, msg):
        sk = self.sk
        if self.alg == "ES256":
            return self.sign_ES256(sk, msg)
        elif self.alg == "EdDSA":
            return self.sign_EdDSA(sk, msg)
        else:
            raise Exception("Unknown signing algorithm")
        
    ######################################################################################################################################
    #util functions
    
    def create_jws(self, url, payload, use_jwk=False):
        #JWS according to jose spec , format is {protected: base64url(header), payload: base64url(payload), signature: base64url(signature)}
        
        protected = {
            "alg": "ES256",
            "nonce": self.get_nonce(),
            "url": url
        }

        if use_jwk:
            protected["jwk"] = self.jwk
        else:
            protected["kid"] = self.kid


        encoded_header = b64_url(json.dumps(protected))
        encoded_payload = "" if payload == "" else b64_url(json.dumps(payload))

        to_sign = str.encode("{}.{}".format(encoded_header, encoded_payload), encoding="ascii")
        signature = self.sign(to_sign)
        encoded_signature = b64_url(signature)

        jws = {
            "protected": encoded_header,
            "payload": encoded_payload,
            "signature": encoded_signature
        }

        return jws

    def create_key_authorization(self, token):
        #keyAuthorization = token || '.' || base64url(Thumbprint(accountKey))
        
        if self.jwk is None:
            raise Exception("Error: jwk is not set , can't create key authorization")
        
        jwk_sorted = json.dumps(self.jwk, sort_keys=True, separators=(',', ':')) # use separators to remove spaces
        thumbprint = SHA256.new(str.encode(jwk_sorted, encoding="utf-8")).digest()

        key_authorization = "{}.{}".format(token, b64_url(thumbprint))
        return key_authorization
    
    

    ######################################################################################################################################
    #ACME functions
    def get_directory(self):
        response =  self.server_session.get(self.directory_url)
        if response.status_code != 200:
            raise Exception("Error getting directory")
        
        directory = response.json()
        self.urls["newAccount"], self.urls["newNonce"], self.urls["newOrder"], self.urls["revokeCert"] = directory["newAccount"], directory["newNonce"], directory["newOrder"], directory["revokeCert"]
        return response.json()
        
    def get_nonce(self):
        if self.urls["newNonce"] is None:
            raise Exception("Error: newNonce url is not set")
        
        nonce_request = self.server_session.get(self.urls["newNonce"])
        if nonce_request.status_code != 200 and nonce_request.status_code != 204:
            raise Exception("Error getting nonce")
        return nonce_request.headers["Replay-Nonce"] 

    def create_account(self):
        if self.urls["newAccount"] is None:
            raise Exception("Error: newAccount url is not set")
                
        payload = {
            "termsOfServiceAgreed": True,
            "contact": [MAIL],  
        }

        jws = self.create_jws(self.urls["newAccount"], payload, use_jwk=True)
        newAccount_request = self.server_session.post(self.urls["newAccount"], json=jws)

        if newAccount_request.status_code != 201:
            print(newAccount_request.text)
            print(jws)
            raise Exception("Error creating new account")
        else:
            self.kid = newAccount_request.headers["Location"]
            return newAccount_request.json()
    
    def fetch_orders(self,url):
        if self.kid is None:
            raise Exception("Error: kid is not set")
        
        payload = ""
        jws = self.create_jws(url, payload)
        
        orders_request = self.server_session.post(url, json=jws)
        if orders_request.status_code != 200:
            raise Exception("Error fetching orders")
        return orders_request.json()


    def submit_order(self, domains):
        if self.urls["newOrder"] is None:
            raise Exception("Error: newOrder url is not set")
        payload = {
            "identifiers": [{"type": "dns", "value": domain} for domain in domains]
        }

        jws = self.create_jws(self.urls["newOrder"], payload)
        newOrder_request = self.server_session.post(self.urls["newOrder"], json=jws)

        if newOrder_request.status_code != 201:
            print(newOrder_request.text)
            raise Exception("Error creating new order")
        else:
            return newOrder_request.json()
    
    def fetch_challenges(self, url):
        #url is extracted from the order response
        if url is None:
            raise Exception("Error: challenge url is not set")
        
        payload = "" #zero length JWS payload and thus non JSON according to the ACME RFC8555
        jws = self.create_jws(url, payload)
        challenge_request = self.server_session.post(url, json=jws)

        if challenge_request.status_code != 200:
            raise Exception("Error fetching challenge")
        else:
            return challenge_request.json()
    
    def respond_challenge(self, auth):
        answered_challenge = None
        #challenges is a list of challenges extracted from the order response
        if auth["status"] != "pending":
            return auth
        
        challenges = auth["challenges"]
        
        for challenge in challenges:
            if answered_challenge is not None:
                break
            token = challenge["token"]
            key_authorization = self.create_key_authorization(token)

            if challenge["type"] == "http-01" and self.challenge_type=="http01":
                challenge_http_server.add_challenge(challenge["token"], key_authorization)
                answered_challenge = challenge
            
            elif challenge["type"] == "dns-01" and self.challenge_type=="dns01":
                #res = self.dns_server.add_acme_challenge(token, key_authorization)
                hash = b64_url(SHA256.new(
                        str.encode(key_authorization, encoding="ascii")).digest())
                self.dns_server.add_TXT_record(
                    "_acme-challenge.{}".format(auth["identifier"]["value"]), hash)
                answered_challenge = challenge

        if answered_challenge is None:
            raise Exception("Error: Unable to answer any challenge")
        
        challenge_url = answered_challenge["url"]
        payload = {}  #challenge validation by sending an empty JSON body ("#IN WHICH TYPE IS THIS RETURNED? STRING? BYTES?{}")
        jws = self.create_jws(challenge_url, payload)
        validation_request = self.server_session.post(challenge_url, json=jws)

        if validation_request.status_code != 200:
            raise Exception("Error validating challenge")
        
        return validation_request.json()
    
    
    def check_authorization(self, url):
        #url is extracted from the order response
        if url is None:
            raise Exception("Error: order url is not set")

        payload = ""
        jws = self.create_jws(url, payload)
        poll_request = self.server_session.post(url, json=jws)

        if poll_request.status_code != 200:
            raise Exception("Error polling order")
        
        poll = poll_request.json()
        return poll
        
    
    def poll_authorizations_valid(self, urls):
        #urls is a list of authorization urls extracted from the order response
        total = len(urls)
        validated = 0
        while validated < total:
            for url in urls:
                poll = self.check_authorization(url)
                if poll["status"] == "valid":
                    validated += 1
                    #print("Validated {} out of {} domains".format(validated, total))
                elif poll["status"] == "invalid":
                    #print(poll)
                    raise Exception("Error: authorization is invalid")
                if validated >= total:
                    return True
            time.sleep(POLL_FREQ)        
        return True
    
    def poll_order_ready(self, url):
        #url is extracted from the order response
        if url is None:
            raise Exception("Error: order url is not set")
        
        payload = ""
        
        while True:
            jws = self.create_jws(url, payload)
            poll_request = self.server_session.post(url, json=jws)

            if poll_request.status_code != 200:
                raise Exception("Error polling order")
            
            poll = poll_request.json()
            if poll["status"] == "ready":
                return True
            elif poll["status"] == "invalid":
                raise Exception("Error: order is invalid")
            time.sleep(POLL_FREQ)

    
    def poll_order_valid(self, url):
        #url is extracted from the order response
        if url is None:
            raise Exception("Error: order url is not set")
        
        payload = ""
        while True:
            jws = self.create_jws(url, payload)
            poll_request = self.server_session.post(url, json=jws)

            if poll_request.status_code != 200:
                raise Exception("Error polling order")
            
            poll = poll_request.json()
            if poll["status"] == "valid":
                return poll
            elif poll["status"] == "invalid":
                raise Exception("Error: order is invalid")
            time.sleep(POLL_FREQ)

        
    
    def finalize_order(self, url, csr):
        if url is None:
            raise Exception("Error: order url is not set")
        
        payload = {
            "csr": b64_url(csr)
        }

        jws = self.create_jws(url, payload)
        finalize_request = self.server_session.post(url, json=jws)

        if finalize_request.status_code != 200:
            raise Exception("Error finalizing order")
        else:
            return finalize_request.json()
    
    def get_certificate(self,url):
        if url is None:
            raise Exception("Error: certificate url is not set")
        
        payload = ""
        jws = self.create_jws(url, payload)
        certificate_request = self.server_session.post(url, json=jws)

        if certificate_request.status_code != 200:
            raise Exception("Error getting certificate")
        else:
            return certificate_request.content
    
    def revoke_certificate(self,certificate):
        if self.urls["revokeCert"] is None:
            raise Exception("Error: revokeCert url is not set")
        payload = {
            "certificate": b64_url(certificate)
        }
        jws = self.create_jws(self.urls["revokeCert"], payload)
        revoke_request = self.server_session.post(self.urls["revokeCert"], json=jws)
        if revoke_request.status_code != 200:
            raise Exception("Error revoking certificate")
        else:
            return revoke_request.content


            
        

    


            

                    

  
        
    



    



        



        

    

