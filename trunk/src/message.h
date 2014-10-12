
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
        Message() : mQr(typeQuery), mOpCode(0), mAA(0), mTC(0), mRD(0), mRA(0), mRCode(0) { } 

        // Virtual desctructor
        ~Message();

        // Decode DNS message from buffer
        // @param buffer The buffer to code the message header into.
        // @param size - size of buffer 
        void decode(const char* buffer, const uint size);

        // Function that codes the DNS message
        // @param buffer The buffer to code the message header into.
        // @param size - size of buffer 
        // @param validSize - number of bytes that contain encoded message
        void encode(char* buffer, const uint size, uint &validSize);

        uint getId() const throw() { return mId; }
        void setId(uint id) { mId = id; }

        void setQr(uint newQr) { mQr = newQr; } 

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

        uint mId;
        uint mQr;
        uint mOpCode;
        uint mAA;
        uint mTC;
        uint mRD;
        uint mRA;
        uint mRCode;

        std::vector<QuerySection*> mQueries;
        std::vector<ResourceRecord*> mAnswers;
        std::vector<ResourceRecord*> mAuthorities;
        std::vector<ResourceRecord*> mAdditional;
};
} // namespace
#endif	/* _DNS_MESSAGE_H */

