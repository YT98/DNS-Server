class DNSError(Exception):
    def __init__(self, message, transaction_id: bytes = None, question: bytes = None):
        super().__init__(message)
        self.transaction_id = transaction_id
        self.question = question


class UnknownRecordTypeError(DNSError):
    pass


class FormatError(DNSError):
    pass


class NoRecordError(DNSError):
    pass


class FunctionalityNotImplementedError(DNSError):
    pass
