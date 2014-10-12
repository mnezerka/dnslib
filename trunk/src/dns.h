
#ifndef _DNS_H
#define	_DNS_H

#include <string>
#include <vector>

namespace dns {

typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned char byte;

// maximal length of domain label name
const uint MAX_MSG_LEN = 512;
const uint MAX_LABEL_LEN = 63;
const uint MAX_DOMAIN_LEN = 255;


} // namespace
#endif	/* _DNS_H */

