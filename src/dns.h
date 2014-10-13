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

} // namespace
#endif	/* _DNS_DNS_H */
