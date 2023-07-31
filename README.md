# Instructions to run project:
To run the DNS server assignment, follow these steps:
1. Make sure to have Python 3.7 or higher installed on your machine.
2. Run the server by executing the main module: ```python -m src.main```

To send DNS Queries to the server, use dig (ex:
```dig @0.0.0.0 http://www.example.com```
)

To send Register Requests to the server, use netcat (ex:
```echo -n "\x00\x01\x00\x01\x0c\x07example\x03com\x00\x00\x04\x01\x02\x03\x04" | nc -u 0.0.0.0 8080```
)

# Justification of selected approach:

The DNSServer class serves as the main entry point for the DNS server application. It creates two sockets to handle DNS 
query (port 53) and register requests (port 8080). The server continuously listens for incoming requests on both sockets. When a
request is received, it routes it to either the DNSQueryResolver or RegisterRequestResolver class based on its type.

The DNSQueryResolver processes DNS query requests by reading the data, extracting relevant information. 
The DNSRegister class is then called to resolve the associated IP address. If a match is found, a DNS response is 
generated using the DNSResponseFactory class, including the resolved IP address.

The RegisterRequestResolver class handles DNS register requests using a custom binary format (Register Request Format, 
outlined below). It validates the request, extracts the domain name and IP address, and stores the mapping in the 
DNSRegister class. The choice of a UDP socket and custom binary format for register requests ensures consistency with 
the DNS Query binary object approach. While a typical HTTP server could have been used, the custom format aligns with 
the server's existing structure.

The separation of concerns through different classes (e.g., DNSQueryResolver, DNSResponseFactory, DNSRegister) 
helps organize the codebase and make it more maintainable and scalable.

**Register Request Format**
- Transaction ID (2 bytes): Unique identifier for the request/response
- Record Type (2 bytes): Type of DNS record to be created
- Domain Name Length (1 byte): Length of the domain name in bytes
- Domain Name (variable length): Domain name for the new record
- Record Data Length (2 bytes): Length of the record data in bytes
- Record Data (variable length): DNS Record Data (ex: IP address)

# Solution limitations:
1. The DNS Server implementation does not support all features and security measures that a production-level DNS Server
would require.
2. Error handling and validation are relatively basic.
3. The server does not handle IPv6 queries or responses.
4. The server does not handle CNAME, MX etc. query types.
5. The DNS Register saves records in memory. In a production level server, records should be saved in Zone files or in a
database, or a combination of both. It would also implement caching to improve efficiency.
6. The responses to Register Requests are not fully implemented. It currently only returns the transaction ID followed by a 1 
on successful registration.

# Possible improvements:
1. Add database and zone file capabilties.
2. Enhance error handling and validation.
3. Implement logging to monitor the server.
4. Implement DNS Security features.
5. Allow the server to handle queries with multiple questions.
6. Add configuration options to customize server behaviour (such as setting TTL values).
7. There are a few duplicated lines of code (in the read domain name method for example) that could be moved to a 
utility class.
8. A DNSQueryClass class similar to the DNSRecordType class could be implemented.
9. Create a docker container to run the server (and the database if implemented)
10. Implement Register Request responses.