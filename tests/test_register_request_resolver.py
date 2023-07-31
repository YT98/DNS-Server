import unittest

from src.register_request_resolver import RegisterRequestResolver
from src.custom_types.dns_record_type import DNSRecordType
from src.custom_types.error_types import FormatError
from src.custom_types.register_request import RegisterRequest


class TestRegisterRequestResolver(unittest.TestCase):
    def setUp(self):
        self.resolver = RegisterRequestResolver()

    def test_read_request_valid(self):
        # Test a valid register request with correct format
        request_data = b""
        request_data += b"\x00\x01"  # Transaction ID
        request_data += b"\x00\x01"  # Record Type: 1
        domain_name_length = 12
        request_data += domain_name_length.to_bytes(1, "big")  # Domain Name Length: 9
        request_data += b"\x07example\x03com\x00"  # Domain Name
        request_data += b"\x00\x04"  # Record Data Length: 4
        request_data += b"\x81\x01\x00\x01"  # IP Address: 129.1.0.1

        expected_request = RegisterRequest(
            original_query=request_data,
            transaction_id=b"\x00\x01",
            record_type=DNSRecordType(1),
            domain_name="example.com",
            ip_address="129.1.0.1"
        )

        request = self.resolver.read_request(request_data)
        self.assertEqual(request, expected_request)

    def test_read_request_malformed_request(self):
        # Malformed register request data (record data length doesn't match actual length)
        request_data = b'\x01\x23\x01\x00\x0c\x07example\x03com\x00\x00\x03\x01\x02\x03\x04'
        with self.assertRaises(FormatError):
            self.resolver.read_request(request_data)

    def test_read_request_overflow_error(self):
        # Invalid register request data (Record Data Length too large, causing OverflowError)
        request_data = b'\x00\x01\x00\x01\x0c\x07example\x03com\x00\xFF\xFF\x01\x02\x03\x04'
        with self.assertRaises(FormatError):
            self.resolver.read_request(request_data)

    def test_read_request_empty_domain(self):
        # Register request data with empty domain name
        request_data = b'\x00\x01\x00\x01\x01\x00\x01\x01\x02\x03\x04'
        with self.assertRaises(FormatError):
            self.resolver.read_request(request_data)

    def test_read_request_empty_ip_address(self):
        # Register request data with empty IP Address
        request_data = b'\x00\x01\x00\x01\x0c\x07example\x03com\x00\x00\x00'
        with self.assertRaises(FormatError):
            self.resolver.read_request(request_data)

    def test_validate_request_length_valid(self):
        # Test a valid register request data length and validate it.
        request_data = b""
        request_data += b"\x00\x01"
        request_data += b"\x00\x01"
        request_data += b"\x09"
        request_data += b"\x07example\x03com\x00"
        request_data += b"\x00\x04"
        request_data += b"\x81\x01\x00\x01"

        validation = self.resolver.validate_register_request_length(
            request_data=request_data,
            domain_name_length=7+3+2,
            record_data_length=4
        )
        self.assertTrue(validation)

    def test_validate_request_length_invalid(self):
        # Test an invalid register request data length and validate it.
        request_data = b""
        request_data += b"\x00\x01"
        request_data += b"\x00\x01"
        request_data += b"\x07example\x03com\x00"
        request_data += b"\x00\x04"
        request_data += b"\x81\x01\x00\x01"

        request_data = request_data[:-2]

        validation = self.resolver.validate_register_request_length(
            request_data=request_data,
            domain_name_length=7 + 3 + 2,
            record_data_length=4
        )
        self.assertFalse(validation)

    def test_read_register_request_ip_address(self):
        # Test various valid IP address byte sequences and verify that they are decoded correctly.
        ip_bytes_1 = b"\x81\x01\x01\x01"
        expected_ip_1 = "129.1.1.1"
        self.assertEqual(RegisterRequestResolver.read_register_request_ip_address(ip_bytes_1), expected_ip_1)

        ip_bytes_2 = b"\xC0\xA8\x00\x01"
        expected_ip_2 = "192.168.0.1"
        self.assertEqual(RegisterRequestResolver.read_register_request_ip_address(ip_bytes_2), expected_ip_2)

        ip_bytes_3 = b"\x00\x00\x00\x00"
        expected_ip_3 = "0.0.0.0"
        self.assertEqual(RegisterRequestResolver.read_register_request_ip_address(ip_bytes_3), expected_ip_3)

        ip_bytes_4 = b"\xFF\xFF\xFF\xFF"
        expected_ip_4 = "255.255.255.255"
        self.assertEqual(RegisterRequestResolver.read_register_request_ip_address(ip_bytes_4), expected_ip_4)

        ip_bytes_5 = b"\x0A\x14\x1E\x28"
        expected_ip_5 = "10.20.30.40"
        self.assertEqual(RegisterRequestResolver.read_register_request_ip_address(ip_bytes_5), expected_ip_5)

    def test_read_register_request_domain_name_valid(self):
        # Test a valid domain name byte sequence and verify that it is decoded correctly.
        domain_name_data = b'\x07example\x03com\x00'
        domain_name = self.resolver.read_register_request_domain_name(domain_name_data)
        self.assertEqual("example.com", domain_name)

    def test_read_register_request_domain_name_http_or_https(self):
        # Test domain name with "http://" prefix
        domain_name_data_http = b'\x07http\x07example\x03com\x00'
        domain_name_http = self.resolver.read_register_request_domain_name(domain_name_data_http)
        self.assertEqual("http://example.com", domain_name_http)

        # Test domain name with "https://" prefix
        domain_name_data_https = b'\x08https\x07example\x03com\x00'
        domain_name_https = self.resolver.read_register_request_domain_name(domain_name_data_https)
        self.assertEqual("https://example.com", domain_name_https)

    def test_read_register_request_domain_name_empty(self):
        # Test an empty domain name byte sequence and verify that it returns an empty string.
        domain_name_data = b'\x00'
        domain_name = self.resolver.read_register_request_domain_name(domain_name_data)
        self.assertEqual("", domain_name)

    def test_read_register_request_domain_name_with_dot(self):
        # Test a domain name byte sequence with a trailing dot (invalid format) and verify that it raises a FormatError.
        domain_name_data = b'\x07example.\x03com\x00'
        with self.assertRaises(FormatError):
            self.resolver.read_register_request_domain_name(domain_name_data)

    def test_read_register_request_domain_name_invalid_data(self):
        # Test an invalid input data type (not bytes) and verify that it raises a FormatError.
        # Invalid input data (not of type bytes)
        invalid_data = "not_bytes_data"
        with self.assertRaises(FormatError):
            self.resolver.read_register_request_domain_name(invalid_data)
