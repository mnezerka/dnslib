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
 
This code is licensed under the NCSA Open Source License
https://opensource.org/licenses/NCSA
 
Copyright (c) 2014 Michal Nezerka
All rights reserved.

Developed by: Michal Nezerka
              https://github.com/mnezerka/
              mailto:michal.nezerka@gmail.com

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files
(the "Software"), to deal with the Software without restriction,
including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software,
and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

 * Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimers.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimers in the
   documentation and/or other materials provided with the distribution.
 * Neither the name of Michal Nezerka, nor the names of its contributors
   may be used to endorse or promote products derived from this Software
   without specific prior written permission. 

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR
ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS WITH THE SOFTWARE.
