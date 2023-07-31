import unittest
from src.custom_types.dns_query import DNSQuery
from src.custom_types.dns_query_question import DNSQueryQuestion
from src.custom_types.dns_record_type import DNSRecordType
from src.dns_response_factory import DNSResponseFactory

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


class TestDNSResponseFactory(unittest.TestCase):
    def setUp(self):
        self.factory = DNSResponseFactory()

    def test_generate_response_valid(self):
        dns_query = EXAMPLE_DNS_QUERY

        # Generate the response for the DNS query
        resolved_ip = "127.0.0.1"
        response = self.factory.generate_response(dns_query, resolved_ip)

        # Assert the response has the correct structure and content
        self.assertEqual(response, b'\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01\x00\x00'
                                   b'\x00\x0e\x00\x04\x7f\x00\x00\x01')

    def test_generate_error_response_valid(self):
        # Test generating an error response with a specific error code
        transaction_id = b"\xAB\xCD"  # Sample transaction ID
        error_code = 2  # Sample error code

        response = self.factory.generate_error_response(
            transaction_id=transaction_id,
            error_code=error_code
        )

        # Assert the response has the correct structure and content
        self.assertEqual(b'\xab\xcd\x81\x02\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01', response)

    def test_generate_error_response_no_transaction_id(self):
        # Test generating an error response with a generic transaction ID
        error_code = 3  # Sample error code

        response = self.factory.generate_error_response(error_code=error_code)

        # Assert the response has the correct structure and content with a generic transaction ID
        self.assertEqual(b'\x00\x00\x81\x03\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01', response)

    def test_generate_response_with_custom_transaction_id(self):
        # Test generating a DNS response with a custom transaction ID
        dns_query_question = DNSQueryQuestion(
            domain_name="example.com",
            query_type=DNSRecordType(1),
            query_class=1,
            as_bytes=b"\x07example\x03com\x00\x00\x01\x00\x01"
        )
        dns_query = DNSQuery(
            original_query=b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
            transaction_id=b"\x12\x34",  # Custom transaction ID
            flags=b"\x00\x00",
            question_count=1,
            answer_count=0,
            authority_count=0,
            additional_count=0,
            question=dns_query_question.as_bytes,
            domain_name=dns_query_question.domain_name,
            query_type=dns_query_question.query_type,
            query_class=dns_query_question.query_class
        )
        resolved_ip = "192.168.1.1"
        response = self.factory.generate_response(dns_query=dns_query, resolved_ip=resolved_ip)

        expected_response = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01" \
                            b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x0e\x00\x04\xc0\xa8\x01\x01"

        self.assertEqual(response, expected_response)

    def test_generate_error_response_with_custom_question(self):
        # Test generating a DNS error response with a custom question
        error_code = 3  # Name Error
        transaction_id = b"\x12\x34"
        custom_question = b"\x03www\x06google\x03com\x00\x00\x01\x00\x01"

        response = self.factory.generate_error_response(
            error_code=error_code,
            transaction_id=transaction_id,
            question=custom_question
        )

        expected_response = b"\x124\x81\x03\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01"

        self.assertEqual(response, expected_response)
