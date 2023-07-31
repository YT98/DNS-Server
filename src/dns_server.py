import select
import socket

from src.dns_register import DNSRegister
from src.dns_query_resolver import DNSQueryResolver
from src.dns_response_factory import DNSResponseFactory
from src.register_request_resolver import RegisterRequestResolver
from src.custom_types.error_types import NoRecordError, FormatError, FunctionalityNotImplementedError


class DNSServer:
    """
    DNSServer is responsible for handling DNS query and register request messages.

    Attributes:
    -----------
    dns_response_factory: DNSResponseFactory
        An instance of DNSResponseFactory to generate DNS response messages.
    dns_resolver: DNSQueryResolver
        An instance of DNSQueryResolver to parse and handle DNS query messages.
    dns_register: DNSRegister
        An instance of DNSRegister to manage domain name registrations and IP addresses.
    register_request_resolver: RegisterRequestResolver
        An instance of RegisterRequestResolver to parse and handle DNS register request messages.
    dns_query_socket: socket.socket
        A UDP socket used to receive DNS query messages.
    register_request_socket: socket.socket
        A UDP socket used to receive DNS register request messages.

    Methods:
    --------
    create_dns_query_socket() -> socket.socket
        Creates and binds a UDP socket for receiving DNS query messages.

    create_register_request_socket() -> socket.socket
        Creates and binds a UDP socket for receiving DNS register request messages.

    listen()
        Listens for incoming DNS query and register request messages and handles them accordingly.

    handle_register_request(data: bytes) -> bytes
        Handles a DNS register request message, generates a response, and returns it as bytes.

    generate_register_request_response(data: bytes) -> bytes
        Generates a response for a DNS register request message and returns it as bytes.

    handle_dns_query(data: bytes) -> bytes
        Handles a DNS query message, generates a response, and returns it as bytes.

    generate_dns_query_response(data: bytes) -> bytes
        Generates a response for a DNS query message and returns it as bytes.
    """
    def __init__(self,
                 dns_resolver: DNSQueryResolver,
                 dns_register: DNSRegister,
                 register_request_resolver: RegisterRequestResolver):
        self.dns_response_factory = DNSResponseFactory()
        self.dns_resolver = dns_resolver
        self.dns_register = dns_register
        self.register_request_resolver = register_request_resolver
        self.dns_query_socket = self.create_dns_query_socket()
        self.register_request_socket = self.create_register_request_socket()

    @staticmethod
    def create_dns_query_socket():
        """
        Creates and binds a UDP socket for receiving DNS query messages.

        :return: The created and bound UDP socket.
        """
        dns_query_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns_query_socket.bind(("0.0.0.0", 53))
        return dns_query_socket

    @staticmethod
    def create_register_request_socket():
        """
        Creates and binds a UDP socket for receiving DNS register request messages.

        :return: The created and bound UDP socket.
        """
        register_request_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        register_request_socket.bind(("0.0.0.0", 8080))
        return register_request_socket

    def listen(self):
        """
        Listens for incoming DNS query and register request messages and handles them accordingly.
        """
        print("Server is listening to post 53 for DNS query requests")
        print("Server is listening to post 8080 for DNS register requests")
        while True:
            ready_sockets, _, _ = select.select([self.dns_query_socket, self.register_request_socket], [], [])
            for sock in ready_sockets:
                if sock == self.dns_query_socket:
                    data, client_address = sock.recvfrom(1024)
                    print(f"Received DNS query from {client_address[0]}:{client_address[1]}")
                    dns_response = self.handle_dns_query(data)
                    print(f"DNS Response: {dns_response}")
                    self.dns_query_socket.sendto(dns_response, client_address)
                elif sock == self.register_request_socket:
                    data, client_address = sock.recvfrom(1024)
                    print(f"Received DNS register request from {client_address[0]}:{client_address[1]}")
                    register_request_response = self.handle_register_request(data)
                    self.register_request_socket.sendto(register_request_response, client_address)

    def handle_register_request(self, data: bytes) -> bytes:
        """
        Handles a DNS register request message, generates a response, and returns it as bytes.

        :param data: The raw bytes of the DNS register request message.
        :return: The generated DNS register response message as bytes.
        """
        try:
            return self.generate_register_request_response(data)
        except FormatError as error:
            # Error code 1 (Format Error)
            print(error)
            return self.dns_response_factory.generate_error_response(transaction_id=data[:2], error_code=1)
        except NoRecordError as error:
            # Error code 3 (Name Error)
            print(error)
            return self.dns_response_factory.generate_error_response(transaction_id=data[:2], error_code=3)
        except FunctionalityNotImplementedError as error:
            # Error code 4 (Not Implemented Error)
            print(error)
            return self.dns_response_factory.generate_error_response(transaction_id=data[:2], error_code=4)
        except Exception as error:
            # Error code 2 (Server Failure)
            print(error)
            return self.dns_response_factory.generate_error_response(transaction_id=None, error_code=2)

    def generate_register_request_response(self, data: bytes) -> bytes:
        """
        Generates a response for a DNS register request message and returns it as bytes.

        :param data: The raw bytes of the DNS register request message.
        :return: The generated DNS register response message as bytes.
        """
        register_request = self.register_request_resolver.read_request(data)
        if register_request.record_type.to_string() != "A":
            raise FunctionalityNotImplementedError(
                message=f"Query type {register_request.record_type.to_string()} is not yet implemented.",
                transaction_id=register_request.transaction_id
            )
        print(f"Registration successful. Domain name: {register_request.domain_name}"
              f" IP Address: {register_request.ip_address}")
        return register_request.transaction_id + b"\x01"

    def handle_dns_query(self, data: bytes) -> bytes:
        """
        Handles a DNS query message, generates a response, and returns it as bytes.

        :param data: The raw bytes of the DNS query message.
        :return: The generated DNS query response message as bytes.
        """
        try:
            return self.generate_dns_query_response(data)
        except FormatError as error:
            # Error code 1 (Format Error)
            print(error)
            return self.dns_response_factory.generate_error_response(
                transaction_id=data[:2],
                error_code=1,
                question=error.question
            )
        except NoRecordError as error:
            # Error code 3 (Name Error)
            print(error)
            return self.dns_response_factory.generate_error_response(
                transaction_id=data[:2],
                error_code=3,
                question=error.question
            )
        except FunctionalityNotImplementedError as error:
            # Error code 4 (Not Implemented Error)
            print(error)
            return self.dns_response_factory.generate_error_response(
                transaction_id=data[:2],
                error_code=4,
                question=error.question
            )
        except Exception as error:
            # Error code 2 (Server Failure)
            print(error)
            return self.dns_response_factory.generate_error_response(transaction_id=None, error_code=2)

    def generate_dns_query_response(self, data: bytes) -> bytes:
        """
        Generates a response for a DNS query message and returns it as bytes.

        :param data: The raw bytes of the DNS query message.
        :return: The generated DNS query response message as bytes.
        """
        dns_query = self.dns_resolver.read_query(data)
        if dns_query.query_type.to_string() != "A":
            raise FunctionalityNotImplementedError(
                message=f"Query type {dns_query.query_type.to_string()} is not yet implemented.",
                transaction_id=dns_query.transaction_id,
                question=dns_query.question
            )

        resolved_ip = self.dns_register.resolve_ip(dns_query)
        if resolved_ip is None:
            raise NoRecordError(
                message="Domain cannot be found in our records.",
                transaction_id=dns_query.transaction_id,
                question=dns_query.question
            )

        return self.dns_response_factory.generate_response(dns_query=dns_query, resolved_ip=resolved_ip)
