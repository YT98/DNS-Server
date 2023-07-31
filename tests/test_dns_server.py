import socket
import unittest
from unittest.mock import Mock, patch, MagicMock

from src.dns_register import DNSRegister
from src.dns_query_resolver import DNSQueryResolver
from src.dns_response_factory import DNSResponseFactory
from src.dns_server import DNSServer
from src.register_request_resolver import RegisterRequestResolver
from src.custom_types.dns_query import DNSQuery
from src.custom_types.dns_record_type import DNSRecordType
from src.custom_types.error_types import FormatError, FunctionalityNotImplementedError

EXAMPLE_DNS_QUERY = DNSQuery(
    original_query=b"",
    transaction_id=b"",
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


class TestDnsServer(unittest.TestCase):
    def setUp(self):
        self.dns_query_resolver_mock = MagicMock(spec=DNSQueryResolver)
        self.dns_register_mock = MagicMock(spec=DNSRegister)
        self.register_request_resolver_mock = MagicMock(spec=RegisterRequestResolver)

        self.mock_create_dns_socket = Mock()
        with patch.object(DNSServer, "create_dns_query_socket"), \
                patch.object(DNSServer, "create_register_request_socket"):
            self.dns_server = DNSServer(
                dns_resolver=self.dns_query_resolver_mock,
                dns_register=self.dns_register_mock,
                register_request_resolver=self.register_request_resolver_mock
            )

        # Mock DNSResponseFactory
        self.dns_response_factory_mock = MagicMock(spec=DNSResponseFactory)
        self.dns_response_factory_mock.generate_response.return_value = b"DNS_RESPONSE"
        self.dns_response_factory_mock.generate_error_response.return_value = b"ERROR_RESPONSE"
        self.dns_server.dns_response_factory = self.dns_response_factory_mock

    def test_create_dns_socket(self):
        with patch("socket.socket") as mock_socket_module:
            mock_socket = mock_socket_module.return_value
            mock_socket.bind.return_value = None

            dns_socket = DNSServer.create_dns_query_socket()

            mock_socket_module.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
            mock_socket.bind.assert_called_once_with(("0.0.0.0", 53))

    def test_create_socket_is_called_when_instantiating(self):
        with patch.object(DNSServer, "create_dns_query_socket") as mock_create_dns_query_socket, \
                patch.object(DNSServer, "create_register_request_socket") as mock_create_register_request_socket:
            dns_server = DNSServer(
                dns_resolver=self.dns_register_mock,
                dns_register=self.dns_register_mock,
                register_request_resolver=self.register_request_resolver_mock
            )
            mock_create_dns_query_socket.assert_called_once()
            mock_create_register_request_socket.assert_called_once()

    def test_handle_query_success(self):
        self.dns_query_resolver_mock.read_query.return_value = EXAMPLE_DNS_QUERY
        self.dns_register_mock.resolve_ip.return_value = "192.0.2.1"

        data = b"DNS_QUERY_DATA"
        result = self.dns_server.handle_dns_query(data)
        self.assertEqual(result, b"DNS_RESPONSE")
        self.dns_query_resolver_mock.read_query.assert_called_once_with(data)
        self.dns_register_mock.resolve_ip.assert_called_once_with(EXAMPLE_DNS_QUERY)

    def test_handle_query_format_error(self):
        self.dns_query_resolver_mock.read_query.side_effect = FormatError(message="")

        data = b"\x00\x01\x00\x00\x00"
        result = self.dns_server.handle_dns_query(data)
        self.assertEqual(result, b"ERROR_RESPONSE")
        self.dns_query_resolver_mock.read_query.assert_called_once_with(data)
        self.dns_response_factory_mock.generate_error_response.assert_called_once_with(
            error_code=1,
            transaction_id=b"\x00\x01",
            question=None
        )

    def test_handle_query_no_record_error(self):
        self.dns_query_resolver_mock.read_query.return_value = EXAMPLE_DNS_QUERY
        self.dns_register_mock.resolve_ip.return_value = None

        data = b'\x00\x01\x00\x00'
        result = self.dns_server.handle_dns_query(data)
        self.assertEqual(result, b"ERROR_RESPONSE")
        self.dns_query_resolver_mock.read_query.assert_called_once_with(data)
        self.dns_register_mock.resolve_ip.assert_called_once_with(EXAMPLE_DNS_QUERY)
        self.dns_response_factory_mock.generate_error_response.assert_called_once_with(
            transaction_id=b'\x00\x01',
            error_code=3,
            question=EXAMPLE_DNS_QUERY.question
        )

    def test_handle_query_not_implemented_error(self):
        self.dns_query_resolver_mock.read_query.side_effect = FunctionalityNotImplementedError(
            transaction_id=b'\x00\x01', message="")

        data = b'\x00\x01\x00\x00'
        result = self.dns_server.handle_dns_query(data)
        self.assertEqual(result, b"ERROR_RESPONSE")
        self.dns_query_resolver_mock.read_query.assert_called_once_with(data)
        self.dns_register_mock.resolve_ip.assert_not_called()
        self.dns_response_factory_mock.generate_error_response.assert_called_once_with(
            transaction_id=b'\x00\x01',
            error_code=4,
            question=None
        )


