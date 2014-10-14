/**
 * DNS LIB Globals 
 *
 * Copyright (C) 2014 - Michal Nezerka <michal.nezerka@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * 
 */

#ifndef _DNS_DNS_H
#define	_DNS_DNS_H

namespace dns {

typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned char byte;

// maximal length of domain label name
const uint MAX_MSG_LEN = 512;
const uint MAX_LABEL_LEN = 63;
const uint MAX_DOMAIN_LEN = 255;

// CLASS types
enum eClass {
    // the Internet
    CLASS_IN = 1,
    // the CSNET class (Obsolete)
    CLASS_CS,
    // the CHAOS class
    CLASS_CH,
    // Hesiod
    CLASS_HS
};


// QCLASS types
enum eQClass {
    // the Internet
    QCLASS_IN = 1,
    // the CSNET class (Obsolete)
    QCLASS_CS,
    // the CHAOS class
    QCLASS_CH,
    // Hesiod
    QCLASS_HS,
    // Any class - *
    QCLASS_ASTERISK = 255
};

// RData types
enum eRDataType {
   // a host address
    RDATA_A = 1,
    // an authoritative name server
    RDATA_NS = 2,
    // a mail destination (Obsolete - use MX)
    RDATA_MD = 3,
    // a mail forwarder (Obsolete - use MX)
    RDATA_MF = 4,
    // the canonical name for an alias
    RDATA_CNAME = 5,
    // marks the start of a zone of authority 
    RDATA_SOA = 6,
    // a mailbox domain name (EXPERIMENTAL)
    RDATA_MB = 7,
    // a mail group member (EXPERIMENTAL)
    RDATA_MG = 8,
    // a mail rename domain name (EXPERIMENTAL)
    RDATA_MR = 9,
    // a null RR (EXPERIMENTAL)
    RDATA_NULL = 10,
    // a well known service description
    RDATA_WKS = 11,
    // a domain name pointer
    RDATA_PTR = 12,
    // host information
    RDATA_HINFO = 13,
    // mailbox or mail list information 
    RDATA_MINFO = 14,
    // mail exchange
    RDATA_MX = 15,
    // text strings
    RDATA_TXT = 16,
    // IPv6 address
    RDATA_AAAA = 28,
    // naming authority pointer
    RDATA_NAPTR = 35,
    RDATA_SRV = 0x0021,
    RDATA_A6 = 0x0026,
    RDATA_OPT = 0x0029,
    RDATA_ANY = 0x00ff
};

} // namespace
#endif	/* _DNS_DNS_H */

