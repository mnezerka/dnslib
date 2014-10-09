
#ifndef _DNS_MESSAGE_H
#define	_DNS_MESSAGE_H

#include <string>
#include <vector>

#include "dns.h"
#include "rr.h"
#include "qs.h"
#include "buffer.h"

namespace dns {

/**
 *  Class that represents the DNS Message and is able to code itself
 *  in the corresponding Message format.
 */
class Message {
public:
    // Type of DNS message
    enum Type { Query = 0, Response };

    // Constructor.
    Message() : m_qr(Query) { }
 
    // Decode the message
    void decode(const char* buffer, int size);

    // Encode the message
    void encode(char* buffer, int size);

    uint getID() const throw() { return m_id; }
    uint getQdCount() const throw() { return mQueries.size(); }
    uint getAnCount() const throw() { return mAnswers.size(); }
    uint getNsCount() const throw() { return mAuthorities.size(); }
    uint getArCount() const throw() { return mAdditional.size(); }

    void setID(uint id) { m_id = id; }

    // Returns the DNS message header as a string text.
    std::string asString();

    // Function that logs the whole buffer of a DNS Message
    void log_buffer(const char* buffer, int size) throw();

protected:

    static const uint HDR_OFFSET = 12;

    uint m_id;
    uint m_qr;
    uint m_opcode;
    uint m_aa;
    uint m_tc;
    uint m_rd;
    uint m_ra;
    uint m_rcode;
    
    /**
     *  Function that codes the DNS message header section.
     *  @param buffer The buffer to code the message header into.
     */
    void encodeHeader(char* buffer) throw ();

    void decodeResourceRecords(Buffer &buffer, uint count, std::vector<ResourceRecord*> &list);

      
private:
    static const uint QR_MASK = 0x8000;
    static const uint OPCODE_MASK = 0x7800;
    static const uint AA_MASK = 0x0400;
    static const uint TC_MASK = 0x0200;
    static const uint RD_MASK = 0x0100;
    static const uint RA_MASK = 0x8000;
    static const uint RCODE_MASK = 0x000F;

    std::vector<QuerySection*> mQueries;
    std::vector<ResourceRecord*> mAnswers;
    std::vector<ResourceRecord*> mAuthorities;
    std::vector<ResourceRecord*> mAdditional;
};
} // namespace
#endif	/* _DNS_MESSAGE_H */

