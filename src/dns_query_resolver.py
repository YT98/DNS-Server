from src.custom_types.error_types import FormatError, FunctionalityNotImplementedError
from src.custom_types.dns_query import DNSQuery
from src.custom_types.dns_query_question import DNSQueryQuestion
from src.custom_types.dns_record_type import DNSRecordType


class DNSQueryResolver:
    """
    DNSQueryResolver is responsible for parsing and resolving DNS query messages received by the server.

    Methods:
    --------
    read_query(query_data: bytes) -> DNSQuery:
        Parses the given query_data and returns a DNSQuery object containing the relevant information.

    read_dns_query_question(question_data: bytes) -> DNSQueryQuestion:
        Parses the DNS question section from the given question_data and returns a DNSQueryQuestion object.

    validate_dns_query_length(query_data: bytes, authority_count: int, additional_count: int) -> bool:
        Validates the length of the DNS query data to ensure it matches the expected format.

    Raises:
    -------
    FormatError: If the query data is malformed or does not match the expected format or if domain name is empty.
    FunctionalityNotImplementedError: If the query contains multiple questions, which is not supported by this server.
    UnknownRecordTypeError: If the query contains an unknown DNS record type (not implemented in DNSRecordType enum).
    """
    def __init__(self):
        pass

    def read_query(self, query_data: bytes) -> DNSQuery:
        """
        Reads and parses a DNS query from the given raw bytes.

        :param query_data: The raw bytes representing the DNS query.
        :return: A DNSQuery object containing the parsed query data.
        :raises FormatError: If the query data is malformed or does not match the expected format.
        :raises FunctionalityNotImplementedError: If the query contains multiple questions (not supported).
        """
        transaction_id = query_data[:2]
        flags = query_data[2:4]
        try:
            question_count = int.from_bytes(query_data[4:6], "big")
            answer_count = int.from_bytes(query_data[6:8], "big")
            authority_count = int.from_bytes(query_data[8:10], "big")
            additional_count = int.from_bytes(query_data[10:12], "big")
        except Exception:
            raise FormatError("Malformed query.")

        # Validate query length
        if not self.validate_dns_query_length(query_data=query_data,
                                              authority_count=authority_count,
                                              additional_count=additional_count):
            raise FormatError("Malformed query.")

        question_index_start = 12  # The header section is always 12 bytes long
        # Each additional and authority record sections are two bytes long
        question_index_end = len(query_data) - authority_count * 2 - additional_count * 2
        dns_query_question = self.read_dns_query_question(query_data[question_index_start:question_index_end])

        if dns_query_question.domain_name == "":
            raise FormatError("Empty domain name.")

        dns_query = DNSQuery(
            original_query=query_data,
            transaction_id=transaction_id,
            flags=flags,
            question_count=question_count,
            answer_count=answer_count,
            authority_count=authority_count,
            additional_count=additional_count,
            question=dns_query_question.as_bytes,
            domain_name=dns_query_question.domain_name,
            query_type=dns_query_question.query_type,
            query_class=dns_query_question.query_class
        )

        if question_count > 1:
            raise FunctionalityNotImplementedError(
                message="This server does not handle queries with multiple questions.",
                transaction_id=transaction_id
            )

        return dns_query

    @staticmethod
    def read_dns_query_question(question_data: bytes) -> DNSQueryQuestion:
        """
        Parses the DNS question section from the given question_data and returns a DNSQueryQuestion object.

        :param question_data: The raw bytes representing the DNS question section.
        :return: A DNSQueryQuestion object containing the parsed question data.
        :raises FormatError: If the question_data is malformed or does not match the expected format.
        """
        pointer = 0
        domain_name = ""

        # Handle http:// and https://
        original_question_data = question_data
        if question_data[0] == 7 and question_data[1:5] == b"http":
            domain_name += "http://"
            question_data = question_data[5:]
        if question_data[0] == 8 and question_data[1:6] == b"https":
            domain_name += "https://"
            question_data = question_data[6:]

        try:
            while True:
                label_length = question_data[pointer]
                if label_length == 0:
                    # End of domain name
                    break
                elif pointer != 0:
                    # Add . before label if it's not the first one
                    domain_name += "."
                label = question_data[pointer + 1: pointer + 1 + label_length]
                domain_name += label.decode("utf-8")
                pointer += label_length + 1

            if len(question_data) < (pointer + 5):
                # there should be at least 4 bytes after pointer for query_type and query_class
                raise FormatError("Malformed query.")
            query_type = int.from_bytes(question_data[pointer + 1: pointer + 3], "big")
            query_class = int.from_bytes(question_data[pointer + 3: pointer + 5], "big")

            return DNSQueryQuestion(
                domain_name=domain_name,
                query_type=DNSRecordType(query_type),
                query_class=query_class,
                as_bytes=original_question_data
            )
        except Exception:
            raise FormatError("Malformed query.")

    @staticmethod
    def validate_dns_query_length(query_data:bytes, authority_count: int, additional_count: int) -> bool:
        """
        Validates the length of the DNS query data to ensure it matches the expected format.

        :param query_data: The raw bytes representing the DNS query.
        :param authority_count: The number of authority records in the DNS query.
        :param additional_count: The number of additional records in the DNS query.
        :return: True if the query data length is valid, False otherwise.
        """
        # Query should be longer than header (12 bytes) plus authorization and additional record sections (2 bytes each)
        return len(query_data) > 12 + authority_count * 2 + additional_count * 2
