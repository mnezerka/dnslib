
#include <iostream>

#include "message.h"
#include "rr.h"
#include "buffer.h"
#include "assert.h"

using namespace std;

void testBuffer()
{
    // check decoding of character string
    char b1[] = {'\x05', 'h', 'e', 'l', 'l', 'o', '\x00', 'a', 'h', 'o', 'j' };
    dns::Buffer b(b1, sizeof(b1));

    std::string strCheck = b.getDnsCharacterString();
    assert (strCheck == "hello");

    strCheck = b.getDnsCharacterString();
    assert (strCheck == ""); 

    // check decoding of domain name
    char b2[] = "\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00";
    dns::Buffer buff2(b2, sizeof(b2) - 1);
    strCheck  = buff2.getDnsDomainName();
    assert (strCheck == "www.google.com"); 
}

void testNAPTR()
{
    dns::RDataNAPTR r;

    char naptr1[] = "\x00\x32\x00\x33\x01\x73\x07\x53\x49\x50\x2b\x44\x32\x54\x00\x04\x5f\x73\x69\x70\x04\x5f\x74\x63\x70\x05\x69\x63\x73\x63\x66\x05\x62\x72\x6e\x35\x36\x03\x69\x69\x74\x03\x69\x6d\x73\x00";
    dns::Buffer b(naptr1, sizeof(naptr1) - 1);
    r.decode(b);
    assert (r.getOrder() == 50);
    assert (r.getPreference() == 51);
    assert (r.getFlags() == "s");
    assert (r.getServices() == "SIP+D2T");
    assert (r.getRegExp() == "");
    assert (r.getReplacement() == "_sip._tcp.icscf.brn56.iit.ims");
}

void testPacket()
{
    // check header without any queries and records
    char packet1[] = "\xd5\xad\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00";
    dns::Message m1;
    m1.decode(packet1, sizeof(packet1) - 1);
    assert (m1.getId() == 0xd5ad);
    assert (m1.getOpCode() == 0);
    assert (m1.getAA() == 0);
    assert (m1.getTC() == 0);
    assert (m1.getRD() == 1);
    assert (m1.getRA() == 1);
    assert (m1.getRCode() == 0);
    assert (m1.getQdCount() == 0);
    assert (m1.getAnCount() == 0);
    assert (m1.getNsCount() == 0);
    assert (m1.getArCount() == 0);

    // check raw resource records
    char packet2[] = "\xd5\xad\x81\x80\x00\x01\x00\x05\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x05\x00\x08\x03\x77\x77\x77\x01\x6c\xc0\x10\xc0\x2c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\x42\xf9\x5b\x68\xc0\x2c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\x42\xf9\x5b\x63\xc0\x2c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\x42\xf9\x5b\x67\xc0\x2c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\x42\xf9\x5b\x93";
    m1.decode(packet2, sizeof(packet2) - 1);
    assert (m1.getQdCount() == 1);
    assert (m1.getAnCount() == 5);
    assert (m1.getNsCount() == 0);
    assert (m1.getArCount() == 0);

    // check naptr resource records
    char packet3[] = "\x14\x38\x85\x80\x00\x01\x00\x03\x00\x00\x00\x00\x05\x62\x72\x6e\x35\x36\x03\x69\x69\x74\x03\x69\x6d\x73\x00\x00\x23\x00\x01\xc0\x0c\x00\x23\x00\x01\x00\x00\x00\x3c\x00\x2e\x00\x32\x00\x33\x01\x73\x07\x53\x49\x50\x2b\x44\x32\x54\x00\x04\x5f\x73\x69\x70\x04\x5f\x74\x63\x70\x05\x69\x63\x73\x63\x66\x05\x62\x72\x6e\x35\x36\x03\x69\x69\x74\x03\x69\x6d\x73\x00\xc0\x4a\x00\x23\x00\x01\x00\x00\x00\x3c\x00\x2f\x00\x0a\x00\x0a\x01\x73\x07\x53\x49\x50\x2b\x44\x32\x53\x00\x04\x5f\x73\x69\x70\x05\x5f\x73\x63\x74\x70\x05\x69\x63\x73\x63\x66\x05\x62\x72\x6e\x35\x36\x03\x69\x69\x74\x03\x69\x6d\x73\x00\xc0\x85\x00\x23\x00\x01\x00\x00\x00\x3c\x00\x2e\x00\x32\x00\x32\x01\x73\x07\x53\x49\x50\x2b\x44\x32\x55\x00\x04\x5f\x73\x69\x70\x04\x5f\x75\x64\x70\x05\x69\x63\x73\x63\x66\x05\x62\x72\x6e\x35\x36\x03\x69\x69\x74\x03\x69\x6d\x73\x00";
    m1.decode(packet3, sizeof(packet3) - 1);
    assert (m1.getQdCount() == 1);
    assert (m1.getAnCount() == 3);
    assert (m1.getNsCount() == 0);
    assert (m1.getArCount() == 0);
}

void testCreatePacket()
{
    dns::Message answer;
    answer.setId(45);
    answer.setQr(dns::Message::typeResponse);

    // add NAPTR answer
    dns::ResourceRecord *rr = new dns::ResourceRecord();
    rr->setType(dns::ResourceRecord::typeNAPTR);
    rr->setClass(dns::ResourceRecord::ClassIN);
    rr->setTtl(60);
    dns::RDataNAPTR *rdata = new dns::RDataNAPTR();
    rdata->setOrder(50);
    rdata->setPreference(51);
    rdata->setServices("SIP+D2T");
    rdata->setRegExp("");
    rdata->setReplacement("_sip._tcp.icscf.brn56.iit.ims");
    rr->setRData(rdata);

    answer.addAnswer(rr);

    dns::uint mesgSize;
    char mesg[2000];
    answer.encode(mesg, 2000, mesgSize);

    // todo check buffer
}

int main(int argc, char** argv)
{
    testBuffer();
    testNAPTR();
    testPacket();
    testCreatePacket();

    return 0;
}
