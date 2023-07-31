from src.custom_types.dns_record_type import DNSRecordType
from src.custom_types.error_types import FormatError
from src.custom_types.register_request import RegisterRequest


class RegisterRequestResolver:
    """
    RegisterRequestResolver is responsible for parsing and resolving register requests received by the server.

    Structure of a Register Request:
    ------------------------------
    - Transaction ID: 2 bytes (16 bits) - A unique identifier for the request.
    - Record Type: 2 bytes (16 bits) - An integer representing the type of DNS record being requested.
    - Domain Name Length: 1 byte (8 bits) - The length of the domain name in bytes.
        (the empty bit at the end of the domain name is not counted)
    - Domain Name: Variable length - The domain name as a sequence of ASCII characters.
    - Record Data Length: 2 bytes (16 bits) - The length of the record data in bytes.
    - Record Data: Variable length - The data associated with the DNS record.

    Record Data Encoding for IPv4 Address:
    --------------------------------------
    For an IPv4 address, the record data is encoded as a sequence of 4 bytes representing the numbers of the IP address.
    For example, the IP address "129.1.1.1" would be encoded as: b"\x81\x01\x01\x01".

    Methods:
    --------
    read_request(request_data: bytes) -> RegisterRequest:
        Parses the given request_data and returns a RegisterRequest object containing the relevant information.
    read_register_request_domain_name(domain_name_data: bytes) -> str:
        Decodes the domain name from the given domain_name_data and returns it as a string.
    validate_register_request_length(request_data: bytes, domain_name_length: int, record_data_length: int) -> bool:
        Validates the length of the register request data to ensure it matches the expected format.
    """
    def read_request(self, request_data: bytes) -> RegisterRequest:
        """
        Reads and parses a register request from the given raw bytes.

        :param request_data: The raw bytes representing the register request.
        :return: A RegisterRequest object containing the parsed request data.
        :raises FormatError: If the request data is malformed or does not match the expected format.
        """
        try:
            transaction_id = request_data[:2]
            record_type = int.from_bytes(request_data[2:4], "big")
            domain_name_length = int.from_bytes(request_data[4:5], "big")
            domain_name_index_start = 5
            domain_name_index_end = 5 + domain_name_length + 1
            record_data_length = int.from_bytes(request_data[domain_name_index_end:domain_name_index_end + 2],
                                                "big")

            if not self.validate_register_request_length(request_data=request_data,
                                                         domain_name_length=domain_name_length,
                                                         record_data_length=record_data_length):
                raise FormatError("Malformed register request.")

            domain_name = self.read_register_request_domain_name(
                request_data[domain_name_index_start:domain_name_index_end])
            if domain_name == "":
                raise Exception

            ip_address = self.read_register_request_ip_address(
                request_data[domain_name_index_end+2:])
            if ip_address == "":
                raise Exception

            return RegisterRequest(
                original_query=request_data,
                transaction_id=transaction_id,
                record_type=DNSRecordType(record_type),
                domain_name=domain_name,
                ip_address=ip_address
            )
        except Exception:
            raise FormatError("Malformed register request.")

    @staticmethod
    def read_register_request_domain_name(domain_name_data: bytes) -> str:
        """
        Decodes the domain name from the given domain_name_data and returns it as a string.

        :param domain_name_data: The raw bytes representing the domain name.
        :return: The decoded domain name as a string.
        :raises FormatError: If the domain name data is malformed or does not match the expected format.
        """
        pointer = 0
        domain_name = ""

        # Handle http:// and https://
        if domain_name_data[0] == 7 and domain_name_data[1:5] == b"http":
            domain_name += "http://"
            domain_name_data = domain_name_data[5:]
        if domain_name_data[0] == 8 and domain_name_data[1:6] == b"https":
            domain_name += "https://"
            domain_name_data = domain_name_data[6:]

        try:
            while True:
                label_length = domain_name_data[pointer]
                if label_length == 0:
                    # End of domain name
                    break
                elif pointer != 0:
                    # Add . before label if it's not the first one
                    domain_name += "."
                label = domain_name_data[pointer + 1: pointer + 1 + label_length]
                domain_name += label.decode("utf-8")
                pointer += label_length + 1

            return domain_name
        except Exception:
            raise FormatError("Malformed register request.")

    @staticmethod
    def read_register_request_ip_address(ip_address_bytes: bytes) -> str:
        """
        Decodes the IP address from the given ip_address_bytes and returns it as a string.

        :param ip_address_bytes: The raw bytes representing the IP address.
        :return: The decoded IP address as a string.
        :raises FormatError: If the IP address data is malformed or does not match the expected format.
        """
        try:
            ip_address = ""
            for i in range(len(ip_address_bytes)):
                if i != 0:
                    ip_address += "."
                ip_address += str(int.from_bytes(ip_address_bytes[i:i+1], "big"))
            return ip_address
        except Exception:
            raise FormatError("Malformed register request.")

    @staticmethod
    def validate_register_request_length(request_data: bytes, domain_name_length: int,
                                         record_data_length: int) -> bool:
        """
        Validates the length of the register request data to ensure it matches the expected format.

        :param request_data: The raw bytes representing the register request.
        :param domain_name_length: The length of the domain name in bytes (excluding the empty bit).
        :param record_data_length: The length of the record data in bytes.
        :return: True if the data length is valid, False otherwise.
        """
        return len(request_data) == 5 + domain_name_length + 1 + 2 + record_data_length
