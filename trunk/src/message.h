
#ifndef _DNS_MESSAGE_H
#define	_DNS_MESSAGE_H

#include <string>
#include <vector>

#include "dns.h"
#include "rr.h"
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

    std::string asString();

protected:

    /* Name of the query */
    std::string mQName;

    /* Type field */
    uint mQType;

    /* Class of the query */
    uint mQClass;
};

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

    /**
     *  Code the message
     *  @param buffer The buffer to code the message into.
     *  @return The size of the buffer coded
     */
    int code(char* buffer) throw();

    /**
     *  decode the message
     *  @param buffer The buffer to decode the message into.
     *  @param size The size of the buffer to decode
     */
    void decode(const char* buffer, int size) throw();

    uint getID() const throw() { return m_id; }
    uint getQdCount() const throw() { return mQueries.size(); }
    uint getAnCount() const throw() { return mAnswers.size(); }
    uint getNsCount() const throw() { return mAuthorities.size(); }
    uint getArCount() const throw() { return mAdditional.size(); }

    void setID(uint id) throw() { m_id = id; }

     /**
     *  Returns the DNS message header as a string text.
     *  @return The string text with the header information.
     */
    std::string asString();

    /**
     *  Function that logs the whole buffer of a DNS Message
     *  @param buffer The buffer to be logged.
     *  @param size The size of the buffer.
     */
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

    std::string decodeDomain(Buffer &buffer) throw();
    void decodeResourceRecords(Buffer &buffer, uint count, std::vector<ResourceRecord*> &list);

    /**
     *  Helper function that get 16 bits from the buffer and keeps it an int.
     *  It helps in compatibility issues as ntohs()
     *  @param buffer The buffer to get the 16 bits from.
     *  @return An int holding the value extracted.
     */
    int get16bits(const char*& buffer) throw();

    /**
     *  Helper function that puts 16 bits into the buffer.
     *  It helps in compatibility issues as htons()
     *  @param buffer The buffer to put the 16 bits into.
     *  @param value An unsigned int holding the value to set the buffer.
     */
    void put16bits(char*& buffer, uint value) throw ();

    /**
     *  Helper function that puts 32 bits into the buffer.
     *  It helps in compatibility issues as htonl()
     *  @param buffer The buffer to put the 32 bits into.
     *  @param value An unsigned long holding the value to set the buffer.
     */
    void put32bits(char*& buffer, ulong value) throw ();

    
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

