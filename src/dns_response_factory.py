import socket

from src.custom_types.dns_query import DNSQuery


class DNSResponseFactory:
    """
    DNSResponseFactory is responsible for generating DNS response messages based on the provided parameters.

    Methods:
    --------
    generate_response(dns_query: DNSQuery, resolved_ip: str) -> bytes:
        Generates a DNS response message containing the resolved IP address for the given DNS query.

    generate_error_response(transaction_id: Optional[bytes], error_code: int) -> bytes:
        Generates a DNS response message for an error condition, based on the provided error code and, optionally,
        the original transaction ID.
    """
    @staticmethod
    def generate_response(dns_query: DNSQuery, resolved_ip: str) -> bytes:
        """
        Generates a DNS response message containing the resolved IP address for the given DNS query.

        :param dns_query: The original DNS query for which the response is generated.
        :param resolved_ip: The IP address associated with the domain name in the DNS query.
        :return: The crafted DNS response message as bytes.
        """
        # Craft the DNS response message
        response = b""
        response += dns_query.transaction_id  # Use the same transaction ID as in the query
        response += b"\x81\x80"  # Standard response (no error)
        response += b"\x00\x01"  # One question
        response += b"\x00\x01"  # One answer
        response += b"\x00\x00"  # No authority records
        response += b"\x00\x00"  # No additional records

        # Add the question section from the original query to the response
        response += dns_query.question

        # Add the answer section to the response
        response += b"\xc0\x0c"  # Pointer to the domain name in the question section
        response += dns_query.query_type.to_bytes()
        response += b"\x00\x01"  # Class is always: IN (Internet)
        response += b"\x00\x00\x00\x0e"  # TTL: 14 seconds (adjust as needed)
        response += b"\x00\x04"  # RDLENGTH: 4 bytes for IPv4 address
        response += socket.inet_aton(resolved_ip)  # RDATA: IPv4 address in binary format

        return response

    @staticmethod
    def generate_error_response(error_code: int, transaction_id: bytes = None, question: bytes = None) -> bytes:
        """
        Generates a DNS response message for an error condition, based on the provided error code and, optionally,
        the original transaction ID and question.

        :param error_code: The error code to be included in the DNS response.
        :param transaction_id: The original transaction ID from the DNS query (optional).
        :param question: The original question from the DNS query (optional).
        :return: The crafted DNS error response message as bytes.
        """
        if question is None:
            question = b"\x00\x00\x00\x00\x00\x01"  # Empty question
        else:
            question = question
        if transaction_id is None:
            transaction_id = b"\x00\x00"  # Generic transaction ID
        else:
            transaction_id = transaction_id  # Original transaction id

        flags = b"\x81" + bytes([error_code])  # Add error code in flags field
        question_count = b"\x00\x01"  # One question
        answer_count = b"\x00\x00"  # No answer
        authority_count = b"\x00\x00"  # No authority record
        additional_count = b"\x00\x00"  # No additional record
        dns_response = transaction_id + flags + question_count + answer_count + authority_count + additional_count

        # Append the question to the response
        dns_response += question

        return dns_response
