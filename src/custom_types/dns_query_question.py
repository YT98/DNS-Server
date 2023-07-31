from dataclasses import dataclass

from src.custom_types.dns_record_type import DNSRecordType


@dataclass
class DNSQueryQuestion:
    domain_name: str
    query_type: DNSRecordType
    query_class: int
    as_bytes: bytes
