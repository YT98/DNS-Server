from src.dns_register import DNSRegister
from src.dns_query_resolver import DNSQueryResolver
from src.dns_server import DNSServer
from src.register_request_resolver import RegisterRequestResolver

dns_query_resolver = DNSQueryResolver()
register_request_resolver = RegisterRequestResolver()
dns_register = DNSRegister()
dns_server = DNSServer(
    dns_resolver=dns_query_resolver,
    dns_register=dns_register,
    register_request_resolver=register_request_resolver
)
dns_server.listen()
