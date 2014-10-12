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

void Message::decode(const char* buffer, const uint bufferSize)
{
    if (bufferSize > MAX_MSG_LEN)
        throw (Exception("Aborting parse of message which exceedes maximal DNS message length."));
    Buffer buff(const_cast<char*>(buffer), bufferSize);   

    // 1. read header
    mId = buff.get16bits();
    uint fields = buff.get16bits();
    mQr = fields & QR_MASK;
    mOpCode = fields & OPCODE_MASK;
    mAA = fields & AA_MASK;
    mTC = fields & TC_MASK;
    mRD = fields & RD_MASK;
    mRA = fields & RA_MASK;
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

    buff.put16bits(mId);
    uint fields = ((mQr & 1) << 15);
    fields += ((mOpCode & 15) << 11);
    fields += ((mAA & 1) << 10);
    fields += ((mTC & 1) << 9);
    fields += ((mRD & 1) << 8);
    fields += ((mRA & 1) << 7);
    fields += ((mRCode & 15));
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
    text << "ID: " << showbase << hex << mId << endl << noshowbase;
    text << "  fields: [ QR: " << mQr << " opCode: " << mOpCode << " ]" << endl;
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


