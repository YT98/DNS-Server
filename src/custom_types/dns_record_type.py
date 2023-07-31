from dataclasses import dataclass

from src.custom_types.error_types import UnknownRecordTypeError


@dataclass
class DNSRecordType:
    value: int

    def __post_init__(self):
        self._record_type_mapping = {
            1: {"str": "A", "bytes": b"\x00\x01"},
            2: {"str": "NS", "bytes": b"\x00\x02"},
            5: {"str": "CNAME", "bytes": b"\x00\x05"},
            6: {"str": "SOA", "bytes": b"\x00\x06"},
            12: {"str": "PTR", "bytes": b"\x00\x0c"},
            15: {"str": "MX", "bytes": b"\x00\x0f"},
            16: {"str": "TXT", "bytes": b"\x00\x10"},
            28: {"str": "AAAA", "bytes": b"\x00\x1c"},
            33: {"str": "SRV", "bytes": b"\x00\x21"},
            255: {"str": "ANY", "bytes": b"\x00\xff"},
        }

        if self.value not in self._record_type_mapping:
            raise UnknownRecordTypeError("Unknown query type.")

    def to_string(self) -> str:
        return self._record_type_mapping[self.value]["str"]

    def to_bytes(self) -> bytes:
        return self._record_type_mapping[self.value]["bytes"]
