from dataclasses import dataclass

from src.custom_types.dns_record_type import DNSRecordType


@dataclass
class DNSQuery:
    original_query: bytes
    transaction_id: bytes
    flags: bytes
    question_count: int
    answer_count: int
    authority_count: int
    additional_count: int
    question: bytes
    domain_name: str
    query_type: DNSRecordType
    query_class: int
