/* 
 * File:   message.cpp
 * Author: tomas
 * 
 * Created on 29 de junio de 2009, 17:39
 */

#include <iostream>
#include <sstream>
#include <cstring>
#include <iomanip>
#include <netinet/in.h>

#include "message.h"
#include "exception.h"

using namespace dns;
using namespace std;

Message::~Message()
{
    // delete all queries
    for(std::vector<QuerySection*>::iterator it = mQueries.begin(); it != mQueries.end(); ++it)
        delete(*it);
    
    // delete answers 
    for(std::vector<ResourceRecord*>::iterator it = mAnswers.begin(); it != mAnswers.end(); ++it)
        delete(*it);

    // delete authorities
    for(std::vector<ResourceRecord*>::iterator it = mAuthorities.begin(); it != mAuthorities.end(); ++it)
        delete(*it);

    // delete additional 
    for(std::vector<ResourceRecord*>::iterator it = mAdditional.begin(); it != mAdditional.end(); ++it)
        delete(*it);
}

void Message::decode(const char* buffer, int bufferSize)
{
    Buffer buff(const_cast<char*>(buffer), bufferSize);   

    // 1. read header
    m_id = buff.get16bits();
    uint fields = buff.get16bits();
    m_qr = fields & QR_MASK;
    m_opcode = fields & OPCODE_MASK;
    m_aa = fields & AA_MASK;
    m_tc = fields & TC_MASK;
    m_rd = fields & RD_MASK;
    m_ra = fields & RA_MASK;
    uint qdCount = buff.get16bits();
    uint anCount = buff.get16bits();
    uint nsCount = buff.get16bits();
    uint arCount = buff.get16bits();

    // 2. read Question Sections
    for (uint i = 0; i < qdCount; i++)
    {
        std::string qName = buff.getDnsDomainName();
        uint qType = buff.get16bits();
        uint qClass = buff.get16bits();

        QuerySection *qs = new QuerySection(qName);
        qs->setType(qType);
        qs->setClass(qClass);
        mQueries.push_back(qs);
    }

    // 3. read Answer Resource Records
    Message::decodeResourceRecords(buff, anCount, mAnswers);
    Message::decodeResourceRecords(buff, nsCount, mAuthorities);
    Message::decodeResourceRecords(buff, arCount, mAdditional);

    // 4. check that buffer is consumed
    if (buff.getPos() != buff.getSize())
        throw(Exception("Message buffer not empty after parsing"));
}

void Message::decodeResourceRecords(Buffer &buffer, uint count, std::vector<ResourceRecord*> &list)
{
    for (uint i = 0; i < count; i++)
    {
        ResourceRecord *rr = new ResourceRecord();
        rr->decode(buffer);
        list.push_back(rr);
    }
}

void Message::encode(char* buffer, const uint bufferSize, uint &validSize)
{
    validSize = 0;
    Buffer buff(buffer, bufferSize);

    // encode header 

    buff.put16bits(m_id);
    uint fields = ((m_qr & 1) << 15);
    fields += ((m_opcode & 15) << 11);
    fields += ((m_aa & 1) << 10);
    fields += ((m_tc & 1) << 9);
    fields += ((m_rd & 1) << 8);
    fields += ((m_ra & 1) << 7);
    fields += ((m_rcode & 15));
    buff.put16bits(fields);
    buff.put16bits(mQueries.size());
    buff.put16bits(mAnswers.size());
    buff.put16bits(mAuthorities.size());
    buff.put16bits(mAdditional.size());

    // encode queries
    for(std::vector<QuerySection*>::iterator it = mQueries.begin(); it != mQueries.end(); ++it)
        (*it)->encode(buff);

    // encode answers 
    for(std::vector<ResourceRecord*>::iterator it = mAnswers.begin(); it != mAnswers.end(); ++it)
        (*it)->encode(buff);

    // encode authorities
    for(std::vector<ResourceRecord*>::iterator it = mAuthorities.begin(); it != mAuthorities.end(); ++it)
        (*it)->encode(buff);

    // encode additional 
    for(std::vector<ResourceRecord*>::iterator it = mAdditional.begin(); it != mAdditional.end(); ++it)
        (*it)->encode(buff);

    validSize = buff.getPos();
}

string Message::asString()
{
    ostringstream text;
    text << "Header:" << endl;
    text << "ID: " << showbase << hex << m_id << endl << noshowbase;
    text << "  fields: [ QR: " << m_qr << " opCode: " << m_opcode << " ]" << endl;
    text << "  QDcount: " << mQueries.size() << endl;
    text << "  ANcount: " << mAnswers.size() << endl;
    text << "  NScount: " << mAuthorities.size() << endl;
    text << "  ARcount: " << mAdditional.size() << endl;

    if (mQueries.size() > 0)
    {
        text << "Queries:" << endl;
        for(std::vector<QuerySection*>::iterator it = mQueries.begin(); it != mQueries.end(); ++it)
            text << "  " << (*it)->asString();
    }

    if (mAnswers.size() > 0)
    {
        text << "Answers:" << endl;
        for(std::vector<ResourceRecord*>::iterator it = mAnswers.begin(); it != mAnswers.end(); ++it)
            text << "  " << (*it)->asString();
    }

    if (mAuthorities.size() > 0)
    {
        text << "Authorities:" << endl;
        for(std::vector<ResourceRecord*>::iterator it = mAuthorities.begin(); it != mAuthorities.end(); ++it)
            text << "  " << (*it)->asString();
    }

    if (mAdditional.size() > 0)
    {
        text << "Additional:" << endl;
        for(std::vector<ResourceRecord*>::iterator it = mAdditional.begin(); it != mAdditional.end(); ++it)
            text << "  " << (*it)->asString();
    }


    return text.str();
}


