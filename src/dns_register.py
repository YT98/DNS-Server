from typing import Optional

from src.dns_response_factory import DNSResponseFactory
from src.custom_types.dns_query import DNSQuery


class DNSRegister:
    """
    DNSRegister is responsible for registering and resolving domain names with associated IP addresses.

    Attributes:
    -----------
    dns_response_factory: DNSResponseFactory
        An instance of DNSResponseFactory to generate DNS response messages.
    records: dict
        A dictionary that maps domain names (str) to their corresponding IP addresses (str).

    Methods:
    --------
    register_domain(domain_name: str, ip_address: str)
        Registers a domain name with the provided IP address.

    resolve_ip(dns_query: DNSQuery) -> Optional[str]
        Resolves the IP address associated with the domain name in the given DNS query.
    """
    def __init__(self):
        self.dns_response_factory = DNSResponseFactory()
        self.records = {
            "https://www.google.com": "172.217.1.110",
            "https://www.yahoo.com": "74.6.231.21",
            "https://www.nhl.com": "104.18.17.236",
            "https://www.python.org": "151.101.193.168"
        }

    def register_domain(self, domain_name: str, ip_address: str):
        """
        Registers a domain name with the provided IP address.

        :param domain_name: The domain name to be registered (e.g., "example.com").
        :param ip_address: The IP address associated with the domain name (e.g., "1.2.3.4").
        """
        self.records[domain_name] = ip_address

    def resolve_ip(self, dns_query: DNSQuery) -> Optional[str]:
        """
        Resolves the IP address associated with the domain name in the given DNS query.

        :param dns_query: The DNS query containing the domain name to be resolved.
        :return: The IP address associated with the domain name if found, None otherwise.
        """
        if dns_query.domain_name in self.records:
            return self.records[dns_query.domain_name]
        else:
            return None
