import unittest

from src.dns_query_resolver import DNSQueryResolver
from src.custom_types.dns_query import DNSQuery
from src.custom_types.dns_record_type import DNSRecordType
from src.custom_types.error_types import FunctionalityNotImplementedError, FormatError


class TestDNSQueryResolver(unittest.TestCase):
    def setUp(self):
        self.dns_resolver = DNSQueryResolver()

    def test_read_query_single_question(self):
        # Example DNS query data
        query_data = b'\x12\x34\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'

        dns_query = self.dns_resolver.read_query(query_data)

        # Check the DNSQuery object attributes
        self.assertIsInstance(dns_query, DNSQuery)
        self.assertEqual(dns_query.transaction_id, b'\x12\x34')
        self.assertEqual(dns_query.flags, b'\x01\x20')
        self.assertEqual(dns_query.question_count, 1)
        self.assertEqual(dns_query.answer_count, 0)
        self.assertEqual(dns_query.authority_count, 0)
        self.assertEqual(dns_query.additional_count, 0)

        # Check the DNSQueryQuestion object attributes
        self.assertEqual(dns_query.question, b'\x07example\x03com\x00\x00\x01\x00\x01')
        self.assertEqual(dns_query.domain_name, 'example.com')
        self.assertEqual(dns_query.query_type, DNSRecordType(1))
        self.assertEqual(dns_query.query_class, 1)

    def test_read_query_multiple_questions(self):
        # Example DNS query data with multiple questions
        query_data = b'\x12\x34\x01\x20\x00\x02\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' \
                     b'\x07example\x03net\x00\x00\x01\x00\x01'

        with self.assertRaises(FunctionalityNotImplementedError):
            self.dns_resolver.read_query(query_data)

    def test_read_query_empty_domain(self):
        # Example DNS query data with empty domain name
        query_data = b'\x12\x34\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01'

        with self.assertRaises(FormatError):
            self.dns_resolver.read_query(query_data)

    def test_read_query_question_valid(self):
        question_data = b"\x03www\x07example\x03com\x00\x00\x01\x00\x01"
        dns_query_question = self.dns_resolver.read_dns_query_question(question_data)
        self.assertEqual(dns_query_question.domain_name, "www.example.com")
        self.assertEqual(dns_query_question.query_type, DNSRecordType(1))
        self.assertEqual(dns_query_question.query_class, 1)
        self.assertEqual(dns_query_question.as_bytes, question_data)

    def test_read_query_question_no_null_pointer(self):
        # No null pointer after domain name
        question_data = b"\x03www\x07example\x03com\x00\x01\x00\x01"
        with self.assertRaises(FormatError):
            self.dns_resolver.read_dns_query_question(question_data)

    def test_read_query_question_empty_domain(self):
        # Empty domain name
        question_data = b"\x00\x00\x01\x00\x01"
        dns_question = self.dns_resolver.read_dns_query_question(question_data)
        self.assertEqual("", dns_question.domain_name)

    def test_read_query_question_too_short(self):
        # No query class
        question_data = b"\x03www\x07example\x03com\x00\x00\x01"
        with self.assertRaises(FormatError):
            self.dns_resolver.read_dns_query_question(question_data)

    def test_read_query_question_with_http_or_https(self):
        # Test domain name with "http://" prefix
        question_data_http = b"\x07http\x03www\x07example\x03com\x00\x00\x01\x00\x01"
        dns_query_question_http = self.dns_resolver.read_dns_query_question(question_data_http)
        self.assertEqual("http://www.example.com", dns_query_question_http.domain_name)

        # Test domain name with "https://" prefix
        question_data_https = b"\x08https\x03www\x07example\x03com\x00\x00\x01\x00\x01"
        dns_query_question_https = self.dns_resolver.read_dns_query_question(question_data_https)
        self.assertEqual("https://www.example.com", dns_query_question_https.domain_name)

    def test_read_dns_query_format_error(self):
        # Example malformed DNS query data with missing null label terminator
        query_data = b'\x12\x34\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x01\x00\x01'
        with self.assertRaises(FormatError):
            self.dns_resolver.read_query(query_data)

    def test_validate_query_length_valid(self):
        query_data = bytes(17)
        authorization_count = 1
        additional_count = 1
        self.assertTrue(DNSQueryResolver.validate_dns_query_length(query_data, authorization_count, additional_count))

        query_data = bytes(13)
        authorization_count = 0
        additional_count = 0
        self.assertTrue(DNSQueryResolver.validate_dns_query_length(query_data, authorization_count, additional_count))

    def test_validate_query_length_malformed(self):
        query_data = bytes(16)
        authorization_count = 3
        additional_count = 5
        self.assertFalse(DNSQueryResolver.validate_dns_query_length(query_data, authorization_count, additional_count))

        authorization_count = 1
        additional_count = 5
        self.assertFalse(DNSQueryResolver.validate_dns_query_length(query_data, authorization_count, additional_count))

    def test_validate_query_length_too_short(self):
        query_data = bytes(0)
        authorization_count = 0
        additional_count = 0
        self.assertFalse(DNSQueryResolver.validate_dns_query_length(query_data, authorization_count, additional_count))

        query_data = bytes(11)
        authorization_count = 0
        additional_count = 0
        self.assertFalse(DNSQueryResolver.validate_dns_query_length(query_data, authorization_count, additional_count))

        query_data = bytes(16)
        authorization_count = 2
        additional_count = 2
        self.assertFalse(DNSQueryResolver.validate_dns_query_length(query_data, authorization_count, additional_count))
