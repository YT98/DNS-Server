from dataclasses import dataclass

from src.custom_types.dns_record_type import DNSRecordType


@dataclass
class RegisterRequest:
    original_query: bytes
    transaction_id: bytes
    record_type: DNSRecordType
    domain_name: str
    ip_address: str
