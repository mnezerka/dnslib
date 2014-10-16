DNS Protocol Library

Simple C++ library designed for encoding and decoding of DNS protocol packets. It doesn't provide
any functionality related to network (listening for packets, sending packets, etc.). Library is strictly
focused on handling of DNS protocol packets - mapping of raw (wire) data to C++ structures (classes)
and vice versa.

Current implementation covers:

 RFC 1035 - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
 RFC 2915 - The Naming Authority Pointer (NAPTR) DNS Resource Record
 RFC 3596 - DNS Extensions to Support IP Version 6

Other tests:

 * checked with valgrind tool (valgrind --leak-check=full ./unittests)
 * linted with cppcheck (cppcheck --enable=all *cpp)
 * fake server tested against Codenomicon DNS suite

