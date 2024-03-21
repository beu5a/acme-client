# DNS Server (Port: 10053): Handles all DNS queries directed by the ACME server.
import threading
from dnslib.server import DNSServer, DNSLogger, BaseResolver
from dnslib.dns import RR, DNSRecord, QTYPE, A, TXT

#inspired by https://paktek123.medium.com/write-your-own-dns-server-in-python-hosted-on-kubernetes-3febacf33b9b



class AcmeDnsResolver(BaseResolver):

    def __init__(self):
        self.zone = {'A': [],'AAAA':[] ,'TXT': [], 'CNAME': []}

    
    def add_TXT_record(self, domain, txt):
        record = RR(domain, QTYPE.TXT, rdata=TXT(txt))
        self.zone['TXT'].append(record)
    
    def add_A_record(self, domain, ip):
        record = RR(domain, QTYPE.A, rdata=A(ip))
        self.zone['A'].append(record)

    def add_AAAA_record(self, domain, ip):
        record = RR(domain, QTYPE.AAAA, rdata=A(ip))
        self.zone['AAAA'].append(record)
    
    def resolve(self, request, handler):
        """
        Resolve DNS queries to the appropriate zone records based on QTYPE.

        Args:
            request: The incoming DNS request object.
            handler: The DNS request handler object.

        Returns:
            The reply object with the appropriate DNS RR answers added.
        """
        reply = request.reply()
        qname = request.q.qname
        qtype = request.q.qtype

        # Define a mapping of QTYPEs to zone keys
        qtype_zone_mapping = {
            QTYPE.A: 'A',
            QTYPE.AAAA: 'AAAA',
            QTYPE.TXT: 'TXT',
        }

        # Check if the QTYPE is one that we're handling
        zone_key = qtype_zone_mapping.get(qtype)
        if zone_key:
            # Check each record in the zone of the current QTYPE
            for record in self.zone.get(zone_key, []):
                if qname.matchGlob(record.rname):
                    reply.add_answer(record)

        return reply



# DNS Server (Port: 10053): Handles all DNS queries directed by the ACME server.
class AcmeDnsServer:
    def __init__(self, port = 10053):
        self.port = port
        self.resolver = AcmeDnsResolver()
        self.logger = DNSLogger()
        self.server = DNSServer(self.resolver, port=self.port,address='0.0.0.0', logger=self.logger)

    def add_A_record(self, domain, ip):
        self.resolver.add_A_record(domain, ip)

    def add_TXT_record(self, domain, txt):
        self.resolver.add_TXT_record(domain, txt)

    def add_AAAA_record(self, domain, ip):
        self.resolver.add_AAAA_record(domain, ip)

    def start(self):
        self.server_thread = threading.Thread(target=self.server.start)
        self.server_thread.start()
        print(f"DNS Server started on port {self.port}")

    def stop(self):
        self.server.stop()

    
