import unittest
from src.custom_types.dns_query import DNSQuery
from src.dns_response_factory import DNSResponseFactory
from src.dns_register import DNSRegister
from src.custom_types.dns_record_type import DNSRecordType

EXAMPLE_DNS_QUERY = DNSQuery(
    original_query=b"",
    transaction_id=b"\x00\x01",
    flags=b"",
    question_count=1,
    answer_count=0,
    authority_count=0,
    additional_count=1,
    question=b"",
    domain_name="example.com",
    query_type=DNSRecordType(1),
    query_class=1
)


class TestDNSRegister(unittest.TestCase):
    def setUp(self):
        self.register = DNSRegister()
        self.dns_response_factory = DNSResponseFactory()

    def test_register_domain(self):
        domain_name = "www.example.com"
        ip_address = "1.1.1.1"
        self.register.register_domain(domain_name, ip_address)

        # Verify that the domain and IP address are registered
        self.assertEqual(self.register.records[domain_name], ip_address)

    def test_resolve_ip_registered(self):
        domain_name = "www.example.com"
        ip_address = "1.1.1.1"
        dns_query = EXAMPLE_DNS_QUERY
        dns_query.domain_name = domain_name
        dns_query.query_type = DNSRecordType(1)
        self.register.register_domain(domain_name, ip_address)

        # Verify that the DNS query is resolved to the correct IP address
        resolved_ip = self.register.resolve_ip(dns_query)
        self.assertEqual(resolved_ip, ip_address)

    def test_resolve_ip_not_registered(self):
        domain_name = "www.example.com"
        dns_query = EXAMPLE_DNS_QUERY
        dns_query.domain_name = domain_name
        dns_query.query_type = DNSRecordType(1)

        # Verify that the DNS query returns None for an unregistered domain
        resolved_ip = self.register.resolve_ip(dns_query)
        self.assertIsNone(resolved_ip)

    def test_generate_response_registered(self):
        domain_name = "www.example.com"
        ip_address = "1.1.1.1"
        dns_query = EXAMPLE_DNS_QUERY
        dns_query.domain_name = domain_name
        dns_query.query_type = DNSRecordType(1)

        self.register.register_domain(domain_name, ip_address)

        # Generate the DNS response for a registered domain
        response = self.dns_response_factory.generate_response(dns_query, ip_address)

        # Verify that the response contains the correct IP address
        self.assertIn(b"\x01\x01\x01\x01", response)
