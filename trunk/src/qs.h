
#ifndef _DNS_QS_H
#define	_DNS_QS_H

#include <string>
#include <vector>

#include "dns.h"
#include "buffer.h"

namespace dns {

/* Class for a DNSQuery */
class QuerySection
{
public:

    /* Constructor */
    QuerySection(const std::string& qName = "") : mQName(qName), mQType(0), mQClass(0) { };

    /* Set type of the query */
    void setType(uint qType) { mQType = qType; };

    /* Set type class of the query */
    void setClass(uint qClass) { mQClass = qClass; };

    /* Set name field from a string */
    void setName(const std::string& qName) { mQName = qName; } ;

    /* Get name filed of the query */
    std::string getName() const;

    /* Get the type of the query */
    uint getType() const;

    /* Get the class of the query */
    uint getClass() const;

    void encode(Buffer &buffer);

    std::string asString();

protected:

    /* Name of the query */
    std::string mQName;

    /* Type field */
    uint mQType;

    /* Class of the query */
    uint mQClass;
};

} // namespace
#endif	/* _DNS_QS_H */

