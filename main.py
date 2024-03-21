import os
import threading
from pathlib import Path
import argparse
import time


from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from acme_client import ACMEClient
from dns_server import AcmeDnsServer
from certificate_https_server import run_server as run_https_server
from challenge_http_server import run_server as run_challenge_server
from shutdown_http_server import  run_server as run_shutdown_server
from utils import gen_key_cert, write_cert


key_path =  "key.pem"
cert_path = "cert.pem"




def obtain_certificate(dns_server,challenges,dir,record,domains,revoke):

    print("ACME client: Starting ACME client, domains: ", domains, " challenge type: ", challenges)
    acme_client = ACMEClient(dir,dns_server,challenge_type=challenges)
    print("ACME client: Signing algorithm: ", acme_client.alg)

    for domain in domains:
        dns_server.add_A_record(domain, record)

    acme_client.get_directory()

    dns_server.start()

    #create a threading file to handle threading
    challenge_server_thread = threading.Thread(target=run_challenge_server)
    challenge_server_thread.daemon = True
    challenge_server_thread.start()

    shutdown_server_thread = threading.Thread(target=run_shutdown_server)
    shutdown_server_thread.daemon = True
    shutdown_server_thread.start()


    

    account = acme_client.create_account()
    print("ACME client: Account created")
    order_urls = account["orders"]
    order = acme_client.submit_order(domains)
    print("ACME client: Order submitted for domains: ", domains)

    #This fetches all the authorizations for the domains , one authorization per domain
    
    auth_urls = order["authorizations"]
    finalize_url = order["finalize"]
    orders_list = acme_client.fetch_orders(order_urls)["orders"]
    
    #this fetches the possible challenges for each authorization
    for auth_url in auth_urls:
        auth = acme_client.fetch_challenges(auth_url) #rename to fetch auth ? 
        response = acme_client.respond_challenge(auth)

    print("ACME client: Challenges completed")

    
    

    ready = acme_client.poll_authorizations_valid(auth_urls)
    print("ACME client: Authorizations valid")
    order_ready = acme_client.poll_order_ready(orders_list[0])
    print("ACME client: Order ready for finalization")
    
    key,csr,der = gen_key_cert(domains)
    final = acme_client.finalize_order(finalize_url,der)
    order_validated = acme_client.poll_order_valid(orders_list[0])
    print("ACME client: Order validated and certificate issued for domains: ", domains)
    
    cert = acme_client.get_certificate(order_validated["certificate"])
    write_cert(key,cert,key_path,cert_path)
    print("ACME client: certificate written to ", cert_path)
    
    
    https_server = threading.Thread(target=run_https_server)
    https_server.daemon = True
    https_server.start()
    
    
    cert_bytes = x509.load_pem_x509_certificate(cert).public_bytes(serialization.Encoding.DER)


    if revoke:
        rev = acme_client.revoke_certificate(cert_bytes)
        print("ACME client: Certificate revoked for domains: ", domains)

    #clean up
    try :
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("Shutting down DNS server")
        dns_server.stop()
        print("Shutting down HTTP servers")
        print("Exiting ACME client")
        os._exit(os.EX_OK)




def main(args):
    dns_server = AcmeDnsServer()
    obtain_certificate(dns_server,args.challenge,args.dir,args.record,args.domain,args.revoke)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("challenge", choices=["dns01", "http01"])
    parser.add_argument("--dir", required=True)
    parser.add_argument("--record", required=True)
    parser.add_argument("--domain", action="append")
    parser.add_argument("--revoke", action="store_true")

    args = parser.parse_args()
    print(" arguments: ", args)
    main(args)

