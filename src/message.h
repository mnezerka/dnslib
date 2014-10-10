
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
        static const uint typeQuery = 0;
        static const uint typeResponse = 1;

        // Constructor.
        Message() : m_qr(typeQuery), m_opcode(0), m_aa(0), m_tc(0), m_rd(0), m_ra(0), m_rcode(0) { } 

        // Virtual desctructor
        ~Message();

        // Decode DNS message from buffer
        // @param buffer The buffer to code the message header into.
        // @param size - size of buffer 
        void decode(const char* buffer, int size);

        // Function that codes the DNS message
        // @param buffer The buffer to code the message header into.
        // @param size - size of buffer 
        // @param validSize - number of bytes that contain encoded message
        void encode(char* buffer, const uint size, uint &validSize);

        uint getID() const throw() { return m_id; }
        void setID(uint id) { m_id = id; }

        void setQR(uint newQR) { m_qr = newQR; } 

        uint getQdCount() { return mQueries.size(); }
        uint getAnCount() { return mAnswers.size(); }
        uint getNsCount() { return mAuthorities.size(); }
        uint getArCount() { return mAdditional.size(); }

        void addQuery(QuerySection *qs) { mQueries.push_back(qs); };
        void addAnswer(ResourceRecord *rr) { mAnswers.push_back(rr); };
        void addAuthority(ResourceRecord *rr) { mAuthorities.push_back(rr); };
        void addAdditional(ResourceRecord *rr) { mAdditional.push_back(rr); };

        // Returns the DNS message header as a string text.
        std::string asString();

    private:
        static const uint HDR_OFFSET = 12;

        static const uint QR_MASK     = 0x8000; 
        static const uint OPCODE_MASK = 0x7800;
        static const uint AA_MASK     = 0x0400;
        static const uint TC_MASK     = 0x0200;
        static const uint RD_MASK     = 0x0100;
        static const uint RA_MASK     = 0x8000;
        static const uint RCODE_MASK  = 0x000F;

        void decodeResourceRecords(Buffer &buffer, uint count, std::vector<ResourceRecord*> &list);

        uint m_id;
        uint m_qr;
        uint m_opcode;
        uint m_aa;
        uint m_tc;
        uint m_rd;
        uint m_ra;
        uint m_rcode;

        std::vector<QuerySection*> mQueries;
        std::vector<ResourceRecord*> mAnswers;
        std::vector<ResourceRecord*> mAuthorities;
        std::vector<ResourceRecord*> mAdditional;
};
} // namespace
#endif	/* _DNS_MESSAGE_H */

