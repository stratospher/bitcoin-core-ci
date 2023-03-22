// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/bip324_vectors.json.h>

#include <chainparams.h>
#include <clientversion.h>
#include <compat/compat.h>
#include <crypto/bip324_suite.h>
#include <cstdint>
#include <key.h>
#include <key_io.h>
#include <net.h>
#include <net_processing.h>
#include <netaddress.h>
#include <netbase.h>
#include <netmessagemaker.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <timedata.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/system.h>
#include <validation.h>
#include <version.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <ios>
#include <memory>
#include <optional>
#include <string>

#include <univalue.h>

using namespace std::literals;

BOOST_FIXTURE_TEST_SUITE(net_tests, RegTestingSetup)

BOOST_AUTO_TEST_CASE(cnode_listen_port)
{
    // test default
    uint16_t port{GetListenPort()};
    BOOST_CHECK(port == Params().GetDefaultPort());
    // test set port
    uint16_t altPort = 12345;
    BOOST_CHECK(gArgs.SoftSetArg("-port", ToString(altPort)));
    port = GetListenPort();
    BOOST_CHECK(port == altPort);
}

BOOST_AUTO_TEST_CASE(cnode_simple_test)
{
    NodeId id = 0;

    in_addr ipv4Addr;
    ipv4Addr.s_addr = 0xa0b0c001;

    CAddress addr = CAddress(CService(ipv4Addr, 7777), NODE_NETWORK);
    std::string pszDest;

    std::unique_ptr<CNode> pnode1 = std::make_unique<CNode>(id++,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/0,
                                                            /*nLocalHostNonceIn=*/0,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::OUTBOUND_FULL_RELAY,
                                                            /*inbound_onion=*/false);
    BOOST_CHECK(pnode1->IsFullOutboundConn() == true);
    BOOST_CHECK(pnode1->IsManualConn() == false);
    BOOST_CHECK(pnode1->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode1->IsFeelerConn() == false);
    BOOST_CHECK(pnode1->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode1->IsInboundConn() == false);
    BOOST_CHECK(pnode1->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode1->ConnectedThroughNetwork(), Network::NET_IPV4);

    std::unique_ptr<CNode> pnode2 = std::make_unique<CNode>(id++,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/1,
                                                            /*nLocalHostNonceIn=*/1,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::INBOUND,
                                                            /*inbound_onion=*/false);
    BOOST_CHECK(pnode2->IsFullOutboundConn() == false);
    BOOST_CHECK(pnode2->IsManualConn() == false);
    BOOST_CHECK(pnode2->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode2->IsFeelerConn() == false);
    BOOST_CHECK(pnode2->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode2->IsInboundConn() == true);
    BOOST_CHECK(pnode2->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode2->ConnectedThroughNetwork(), Network::NET_IPV4);

    std::unique_ptr<CNode> pnode3 = std::make_unique<CNode>(id++,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/0,
                                                            /*nLocalHostNonceIn=*/0,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::OUTBOUND_FULL_RELAY,
                                                            /*inbound_onion=*/false);
    BOOST_CHECK(pnode3->IsFullOutboundConn() == true);
    BOOST_CHECK(pnode3->IsManualConn() == false);
    BOOST_CHECK(pnode3->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode3->IsFeelerConn() == false);
    BOOST_CHECK(pnode3->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode3->IsInboundConn() == false);
    BOOST_CHECK(pnode3->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode3->ConnectedThroughNetwork(), Network::NET_IPV4);

    std::unique_ptr<CNode> pnode4 = std::make_unique<CNode>(id++,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/1,
                                                            /*nLocalHostNonceIn=*/1,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::INBOUND,
                                                            /*inbound_onion=*/true);
    BOOST_CHECK(pnode4->IsFullOutboundConn() == false);
    BOOST_CHECK(pnode4->IsManualConn() == false);
    BOOST_CHECK(pnode4->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode4->IsFeelerConn() == false);
    BOOST_CHECK(pnode4->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode4->IsInboundConn() == true);
    BOOST_CHECK(pnode4->m_inbound_onion == true);
    BOOST_CHECK_EQUAL(pnode4->ConnectedThroughNetwork(), Network::NET_ONION);
}

BOOST_AUTO_TEST_CASE(cnetaddr_basic)
{
    CNetAddr addr;

    // IPv4, INADDR_ANY
    BOOST_REQUIRE(LookupHost("0.0.0.0", addr, false));
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "0.0.0.0");

    // IPv4, INADDR_NONE
    BOOST_REQUIRE(LookupHost("255.255.255.255", addr, false));
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "255.255.255.255");

    // IPv4, casual
    BOOST_REQUIRE(LookupHost("12.34.56.78", addr, false));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "12.34.56.78");

    // IPv6, in6addr_any
    BOOST_REQUIRE(LookupHost("::", addr, false));
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());

    BOOST_CHECK(addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "::");

    // IPv6, casual
    BOOST_REQUIRE(LookupHost("1122:3344:5566:7788:9900:aabb:ccdd:eeff", addr, false));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "1122:3344:5566:7788:9900:aabb:ccdd:eeff");

    // IPv6, scoped/link-local. See https://tools.ietf.org/html/rfc4007
    // We support non-negative decimal integers (uint32_t) as zone id indices.
    // Normal link-local scoped address functionality is to append "%" plus the
    // zone id, for example, given a link-local address of "fe80::1" and a zone
    // id of "32", return the address as "fe80::1%32".
    const std::string link_local{"fe80::1"};
    const std::string scoped_addr{link_local + "%32"};
    BOOST_REQUIRE(LookupHost(scoped_addr, addr, false));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), scoped_addr);

    // Test that the delimiter "%" and default zone id of 0 can be omitted for the default scope.
    BOOST_REQUIRE(LookupHost(link_local + "%0", addr, false));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), link_local);

    // TORv2, no longer supported
    BOOST_CHECK(!addr.SetSpecial("6hzph5hv6337r6p2.onion"));

    // TORv3
    const char* torv3_addr = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
    BOOST_REQUIRE(addr.SetSpecial(torv3_addr));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsTor());

    BOOST_CHECK(!addr.IsI2P());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), torv3_addr);

    // TORv3, broken, with wrong checksum
    BOOST_CHECK(!addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.onion"));

    // TORv3, broken, with wrong version
    BOOST_CHECK(!addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscrye.onion"));

    // TORv3, malicious
    BOOST_CHECK(!addr.SetSpecial(std::string{
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd\0wtf.onion", 66}));

    // TOR, bogus length
    BOOST_CHECK(!addr.SetSpecial(std::string{"mfrggzak.onion"}));

    // TOR, invalid base32
    BOOST_CHECK(!addr.SetSpecial(std::string{"mf*g zak.onion"}));

    // I2P
    const char* i2p_addr = "UDHDrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.I2P";
    BOOST_REQUIRE(addr.SetSpecial(i2p_addr));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsI2P());

    BOOST_CHECK(!addr.IsTor());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), ToLower(i2p_addr));

    // I2P, correct length, but decodes to less than the expected number of bytes.
    BOOST_CHECK(!addr.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jn=.b32.i2p"));

    // I2P, extra unnecessary padding
    BOOST_CHECK(!addr.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna=.b32.i2p"));

    // I2P, malicious
    BOOST_CHECK(!addr.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v\0wtf.b32.i2p"s));

    // I2P, valid but unsupported (56 Base32 characters)
    // See "Encrypted LS with Base 32 Addresses" in
    // https://geti2p.net/spec/encryptedleaseset.txt
    BOOST_CHECK(
        !addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.b32.i2p"));

    // I2P, invalid base32
    BOOST_CHECK(!addr.SetSpecial(std::string{"tp*szydbh4dp.b32.i2p"}));

    // Internal
    addr.SetInternal("esffpp");
    BOOST_REQUIRE(!addr.IsValid()); // "internal" is considered invalid
    BOOST_REQUIRE(addr.IsInternal());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "esffpvrt3wpeaygy.internal");

    // Totally bogus
    BOOST_CHECK(!addr.SetSpecial("totally bogus"));
}

BOOST_AUTO_TEST_CASE(cnetaddr_tostring_canonical_ipv6)
{
    // Test that CNetAddr::ToString formats IPv6 addresses with zero compression as described in
    // RFC 5952 ("A Recommendation for IPv6 Address Text Representation").
    const std::map<std::string, std::string> canonical_representations_ipv6{
        {"0000:0000:0000:0000:0000:0000:0000:0000", "::"},
        {"000:0000:000:00:0:00:000:0000", "::"},
        {"000:000:000:000:000:000:000:000", "::"},
        {"00:00:00:00:00:00:00:00", "::"},
        {"0:0:0:0:0:0:0:0", "::"},
        {"0:0:0:0:0:0:0:1", "::1"},
        {"2001:0:0:1:0:0:0:1", "2001:0:0:1::1"},
        {"2001:0db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:db8:85a3::8a2e:370:7334"},
        {"2001:0db8::0001", "2001:db8::1"},
        {"2001:0db8::0001:0000", "2001:db8::1:0"},
        {"2001:0db8::1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:db8:0000:0:1::1", "2001:db8::1:0:0:1"},
        {"2001:db8:0000:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},
        {"2001:db8:0:0:0:0:2:1", "2001:db8::2:1"},
        {"2001:db8:0:0:0::1", "2001:db8::1"},
        {"2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:db8:0:0:1::1", "2001:db8::1:0:0:1"},
        {"2001:DB8:0:0:1::1", "2001:db8::1:0:0:1"},
        {"2001:db8:0:0::1", "2001:db8::1"},
        {"2001:db8:0:0:aaaa::1", "2001:db8::aaaa:0:0:1"},
        {"2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},
        {"2001:db8:0::1", "2001:db8::1"},
        {"2001:db8:85a3:0:0:8a2e:370:7334", "2001:db8:85a3::8a2e:370:7334"},
        {"2001:db8::0:1", "2001:db8::1"},
        {"2001:db8::0:1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:DB8::1", "2001:db8::1"},
        {"2001:db8::1", "2001:db8::1"},
        {"2001:db8::1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:db8::1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},
        {"2001:db8::aaaa:0:0:1", "2001:db8::aaaa:0:0:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:0:1", "2001:db8:aaaa:bbbb:cccc:dddd:0:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd::1", "2001:db8:aaaa:bbbb:cccc:dddd:0:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:0001", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:001", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:01", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:1", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:AAAA", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:AaAa", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa"},
    };
    for (const auto& [input_address, expected_canonical_representation_output] : canonical_representations_ipv6) {
        CNetAddr net_addr;
        BOOST_REQUIRE(LookupHost(input_address, net_addr, false));
        BOOST_REQUIRE(net_addr.IsIPv6());
        BOOST_CHECK_EQUAL(net_addr.ToStringAddr(), expected_canonical_representation_output);
    }
}

BOOST_AUTO_TEST_CASE(cnetaddr_serialize_v1)
{
    CNetAddr addr;
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);

    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000000000000000");
    s.clear();

    BOOST_REQUIRE(LookupHost("1.2.3.4", addr, false));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000ffff01020304");
    s.clear();

    BOOST_REQUIRE(LookupHost("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b", addr, false));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "1a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
    s.clear();

    // TORv2, no longer supported
    BOOST_CHECK(!addr.SetSpecial("6hzph5hv6337r6p2.onion"));

    BOOST_REQUIRE(addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000000000000000");
    s.clear();

    addr.SetInternal("a");
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "fd6b88c08724ca978112ca1bbdcafac2");
    s.clear();
}

BOOST_AUTO_TEST_CASE(cnetaddr_serialize_v2)
{
    CNetAddr addr;
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    // Add ADDRV2_FORMAT to the version so that the CNetAddr
    // serialize method produces an address in v2 format.
    s.SetVersion(s.GetVersion() | ADDRV2_FORMAT);

    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "021000000000000000000000000000000000");
    s.clear();

    BOOST_REQUIRE(LookupHost("1.2.3.4", addr, false));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "010401020304");
    s.clear();

    BOOST_REQUIRE(LookupHost("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b", addr, false));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "02101a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
    s.clear();

    // TORv2, no longer supported
    BOOST_CHECK(!addr.SetSpecial("6hzph5hv6337r6p2.onion"));

    BOOST_REQUIRE(addr.SetSpecial("kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion"));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "042053cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88");
    s.clear();

    BOOST_REQUIRE(addr.SetInternal("a"));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "0210fd6b88c08724ca978112ca1bbdcafac2");
    s.clear();
}

BOOST_AUTO_TEST_CASE(cnetaddr_unserialize_v2)
{
    CNetAddr addr;
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    // Add ADDRV2_FORMAT to the version so that the CNetAddr
    // unserialize method expects an address in v2 format.
    s.SetVersion(s.GetVersion() | ADDRV2_FORMAT);

    // Valid IPv4.
    s << Span{ParseHex("01"          // network type (IPv4)
                       "04"          // address length
                       "01020304")}; // address
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsIPv4());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "1.2.3.4");
    BOOST_REQUIRE(s.empty());

    // Invalid IPv4, valid length but address itself is shorter.
    s << Span{ParseHex("01"      // network type (IPv4)
                       "04"      // address length
                       "0102")}; // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure, HasReason("end of data"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv4, with bogus length.
    s << Span{ParseHex("01"          // network type (IPv4)
                       "05"          // address length
                       "01020304")}; // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 IPv4 address with length 5 (should be 4)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv4, with extreme length.
    s << Span{ParseHex("01"          // network type (IPv4)
                       "fd0102"      // address length (513 as CompactSize)
                       "01020304")}; // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("Address too long: 513 > 512"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid IPv6.
    s << Span{ParseHex("02"                                  // network type (IPv6)
                       "10"                                  // address length
                       "0102030405060708090a0b0c0d0e0f10")}; // address
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsIPv6());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "102:304:506:708:90a:b0c:d0e:f10");
    BOOST_REQUIRE(s.empty());

    // Valid IPv6, contains embedded "internal".
    s << Span{ParseHex(
        "02"                                  // network type (IPv6)
        "10"                                  // address length
        "fd6b88c08724ca978112ca1bbdcafac2")}; // address: 0xfd + sha256("bitcoin")[0:5] +
                                              // sha256(name)[0:10]
    s >> addr;
    BOOST_CHECK(addr.IsInternal());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "zklycewkdo64v6wc.internal");
    BOOST_REQUIRE(s.empty());

    // Invalid IPv6, with bogus length.
    s << Span{ParseHex("02"    // network type (IPv6)
                       "04"    // address length
                       "00")}; // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 IPv6 address with length 4 (should be 16)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv6, contains embedded IPv4.
    s << Span{ParseHex("02"                                  // network type (IPv6)
                       "10"                                  // address length
                       "00000000000000000000ffff01020304")}; // address
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Invalid IPv6, contains embedded TORv2.
    s << Span{ParseHex("02"                                  // network type (IPv6)
                       "10"                                  // address length
                       "fd87d87eeb430102030405060708090a")}; // address
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // TORv2, no longer supported.
    s << Span{ParseHex("03"                      // network type (TORv2)
                       "0a"                      // address length
                       "f1f2f3f4f5f6f7f8f9fa")}; // address
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Valid TORv3.
    s << Span{ParseHex("04"                               // network type (TORv3)
                       "20"                               // address length
                       "79bcc625184b05194975c28b66b66b04" // address
                       "69f7f6556fb1ac3189a79b40dda32f1f"
                       )};
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsTor());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(),
                      "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion");
    BOOST_REQUIRE(s.empty());

    // Invalid TORv3, with bogus length.
    s << Span{ParseHex("04" // network type (TORv3)
                       "00" // address length
                       "00" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 TORv3 address with length 0 (should be 32)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid I2P.
    s << Span{ParseHex("05"                               // network type (I2P)
                       "20"                               // address length
                       "a2894dabaec08c0051a481a6dac88b64" // address
                       "f98232ae42d4b6fd2fa81952dfe36a87")};
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsI2P());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(),
                      "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p");
    BOOST_REQUIRE(s.empty());

    // Invalid I2P, with bogus length.
    s << Span{ParseHex("05" // network type (I2P)
                       "03" // address length
                       "00" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 I2P address with length 3 (should be 32)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid CJDNS.
    s << Span{ParseHex("06"                               // network type (CJDNS)
                       "10"                               // address length
                       "fc000001000200030004000500060007" // address
                       )};
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsCJDNS());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "fc00:1:2:3:4:5:6:7");
    BOOST_REQUIRE(s.empty());

    // Invalid CJDNS, wrong prefix.
    s << Span{ParseHex("06"                               // network type (CJDNS)
                       "10"                               // address length
                       "aa000001000200030004000500060007" // address
                       )};
    s >> addr;
    BOOST_CHECK(addr.IsCJDNS());
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Invalid CJDNS, with bogus length.
    s << Span{ParseHex("06" // network type (CJDNS)
                       "01" // address length
                       "00" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 CJDNS address with length 1 (should be 16)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Unknown, with extreme length.
    s << Span{ParseHex("aa"             // network type (unknown)
                       "fe00000002"     // address length (CompactSize's MAX_SIZE)
                       "01020304050607" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("Address too long: 33554432 > 512"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Unknown, with reasonable length.
    s << Span{ParseHex("aa"       // network type (unknown)
                       "04"       // address length
                       "01020304" // address
                       )};
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Unknown, with zero length.
    s << Span{ParseHex("aa" // network type (unknown)
                       "00" // address length
                       ""   // address
                       )};
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());
}

// prior to PR #14728, this test triggers an undefined behavior
BOOST_AUTO_TEST_CASE(ipv4_peer_with_ipv6_addrMe_test)
{
    // set up local addresses; all that's necessary to reproduce the bug is
    // that a normal IPv4 address is among the entries, but if this address is
    // !IsRoutable the undefined behavior is easier to trigger deterministically
    in_addr raw_addr;
    raw_addr.s_addr = htonl(0x7f000001);
    const CNetAddr mapLocalHost_entry = CNetAddr(raw_addr);
    {
        LOCK(g_maplocalhost_mutex);
        LocalServiceInfo lsi;
        lsi.nScore = 23;
        lsi.nPort = 42;
        mapLocalHost[mapLocalHost_entry] = lsi;
    }

    // create a peer with an IPv4 address
    in_addr ipv4AddrPeer;
    ipv4AddrPeer.s_addr = 0xa0b0c001;
    CAddress addr = CAddress(CService(ipv4AddrPeer, 7777), NODE_NETWORK);
    std::unique_ptr<CNode> pnode = std::make_unique<CNode>(/*id=*/0,
                                                           /*sock=*/nullptr,
                                                           addr,
                                                           /*nKeyedNetGroupIn=*/0,
                                                           /*nLocalHostNonceIn=*/0,
                                                           CAddress{},
                                                           /*pszDest=*/std::string{},
                                                           ConnectionType::OUTBOUND_FULL_RELAY,
                                                           /*inbound_onion=*/false);
    pnode->fSuccessfullyConnected.store(true);

    // the peer claims to be reaching us via IPv6
    in6_addr ipv6AddrLocal;
    memset(ipv6AddrLocal.s6_addr, 0, 16);
    ipv6AddrLocal.s6_addr[0] = 0xcc;
    CAddress addrLocal = CAddress(CService(ipv6AddrLocal, 7777), NODE_NETWORK);
    pnode->SetAddrLocal(addrLocal);

    // before patch, this causes undefined behavior detectable with clang's -fsanitize=memory
    GetLocalAddrForPeer(*pnode);

    // suppress no-checks-run warning; if this test fails, it's by triggering a sanitizer
    BOOST_CHECK(1);

    // Cleanup, so that we don't confuse other tests.
    {
        LOCK(g_maplocalhost_mutex);
        mapLocalHost.erase(mapLocalHost_entry);
    }
}

BOOST_AUTO_TEST_CASE(get_local_addr_for_peer_port)
{
    // Test that GetLocalAddrForPeer() properly selects the address to self-advertise:
    //
    // 1. GetLocalAddrForPeer() calls GetLocalAddress() which returns an address that is
    //    not routable.
    // 2. GetLocalAddrForPeer() overrides the address with whatever the peer has told us
    //    he sees us as.
    // 2.1. For inbound connections we must override both the address and the port.
    // 2.2. For outbound connections we must override only the address.

    // Pretend that we bound to this port.
    const uint16_t bind_port = 20001;
    m_node.args->ForceSetArg("-bind", strprintf("3.4.5.6:%u", bind_port));

    // Our address:port as seen from the peer, completely different from the above.
    in_addr peer_us_addr;
    peer_us_addr.s_addr = htonl(0x02030405);
    const CService peer_us{peer_us_addr, 20002};

    // Create a peer with a routable IPv4 address (outbound).
    in_addr peer_out_in_addr;
    peer_out_in_addr.s_addr = htonl(0x01020304);
    CNode peer_out{/*id=*/0,
                   /*sock=*/nullptr,
                   /*addrIn=*/CAddress{CService{peer_out_in_addr, 8333}, NODE_NETWORK},
                   /*nKeyedNetGroupIn=*/0,
                   /*nLocalHostNonceIn=*/0,
                   /*addrBindIn=*/CAddress{},
                   /*addrNameIn=*/std::string{},
                   /*conn_type_in=*/ConnectionType::OUTBOUND_FULL_RELAY,
                   /*inbound_onion=*/false};
    peer_out.fSuccessfullyConnected = true;
    peer_out.SetAddrLocal(peer_us);

    // Without the fix peer_us:8333 is chosen instead of the proper peer_us:bind_port.
    auto chosen_local_addr = GetLocalAddrForPeer(peer_out);
    BOOST_REQUIRE(chosen_local_addr);
    const CService expected{peer_us_addr, bind_port};
    BOOST_CHECK(*chosen_local_addr == expected);

    // Create a peer with a routable IPv4 address (inbound).
    in_addr peer_in_in_addr;
    peer_in_in_addr.s_addr = htonl(0x05060708);
    CNode peer_in{/*id=*/0,
                  /*sock=*/nullptr,
                  /*addrIn=*/CAddress{CService{peer_in_in_addr, 8333}, NODE_NETWORK},
                  /*nKeyedNetGroupIn=*/0,
                  /*nLocalHostNonceIn=*/0,
                  /*addrBindIn=*/CAddress{},
                  /*addrNameIn=*/std::string{},
                  /*conn_type_in=*/ConnectionType::INBOUND,
                  /*inbound_onion=*/false};
    peer_in.fSuccessfullyConnected = true;
    peer_in.SetAddrLocal(peer_us);

    // Without the fix peer_us:8333 is chosen instead of the proper peer_us:peer_us.GetPort().
    chosen_local_addr = GetLocalAddrForPeer(peer_in);
    BOOST_REQUIRE(chosen_local_addr);
    BOOST_CHECK(*chosen_local_addr == peer_us);

    m_node.args->ForceSetArg("-bind", "");
}

BOOST_AUTO_TEST_CASE(LimitedAndReachable_Network)
{
    BOOST_CHECK(IsReachable(NET_IPV4));
    BOOST_CHECK(IsReachable(NET_IPV6));
    BOOST_CHECK(IsReachable(NET_ONION));
    BOOST_CHECK(IsReachable(NET_I2P));
    BOOST_CHECK(IsReachable(NET_CJDNS));

    SetReachable(NET_IPV4, false);
    SetReachable(NET_IPV6, false);
    SetReachable(NET_ONION, false);
    SetReachable(NET_I2P, false);
    SetReachable(NET_CJDNS, false);

    BOOST_CHECK(!IsReachable(NET_IPV4));
    BOOST_CHECK(!IsReachable(NET_IPV6));
    BOOST_CHECK(!IsReachable(NET_ONION));
    BOOST_CHECK(!IsReachable(NET_I2P));
    BOOST_CHECK(!IsReachable(NET_CJDNS));

    SetReachable(NET_IPV4, true);
    SetReachable(NET_IPV6, true);
    SetReachable(NET_ONION, true);
    SetReachable(NET_I2P, true);
    SetReachable(NET_CJDNS, true);

    BOOST_CHECK(IsReachable(NET_IPV4));
    BOOST_CHECK(IsReachable(NET_IPV6));
    BOOST_CHECK(IsReachable(NET_ONION));
    BOOST_CHECK(IsReachable(NET_I2P));
    BOOST_CHECK(IsReachable(NET_CJDNS));
}

BOOST_AUTO_TEST_CASE(LimitedAndReachable_NetworkCaseUnroutableAndInternal)
{
    BOOST_CHECK(IsReachable(NET_UNROUTABLE));
    BOOST_CHECK(IsReachable(NET_INTERNAL));

    SetReachable(NET_UNROUTABLE, false);
    SetReachable(NET_INTERNAL, false);

    BOOST_CHECK(IsReachable(NET_UNROUTABLE)); // Ignored for both networks
    BOOST_CHECK(IsReachable(NET_INTERNAL));
}

CNetAddr UtilBuildAddress(unsigned char p1, unsigned char p2, unsigned char p3, unsigned char p4)
{
    unsigned char ip[] = {p1, p2, p3, p4};

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sockaddr_in)); // initialize the memory block
    memcpy(&(sa.sin_addr), &ip, sizeof(ip));
    return CNetAddr(sa.sin_addr);
}


BOOST_AUTO_TEST_CASE(LimitedAndReachable_CNetAddr)
{
    CNetAddr addr = UtilBuildAddress(0x001, 0x001, 0x001, 0x001); // 1.1.1.1

    SetReachable(NET_IPV4, true);
    BOOST_CHECK(IsReachable(addr));

    SetReachable(NET_IPV4, false);
    BOOST_CHECK(!IsReachable(addr));

    SetReachable(NET_IPV4, true); // have to reset this, because this is stateful.
}


BOOST_AUTO_TEST_CASE(LocalAddress_BasicLifecycle)
{
    CService addr = CService(UtilBuildAddress(0x002, 0x001, 0x001, 0x001), 1000); // 2.1.1.1:1000

    SetReachable(NET_IPV4, true);

    BOOST_CHECK(!IsLocal(addr));
    BOOST_CHECK(AddLocal(addr, 1000));
    BOOST_CHECK(IsLocal(addr));

    RemoveLocal(addr);
    BOOST_CHECK(!IsLocal(addr));
}

BOOST_AUTO_TEST_CASE(initial_advertise_from_version_message)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    // Tests the following scenario:
    // * -bind=3.4.5.6:20001 is specified
    // * we make an outbound connection to a peer
    // * the peer reports he sees us as 2.3.4.5:20002 in the version message
    //   (20002 is a random port assigned by our OS for the outgoing TCP connection,
    //   we cannot accept connections to it)
    // * we should self-advertise to that peer as 2.3.4.5:20001

    // Pretend that we bound to this port.
    const uint16_t bind_port = 20001;
    m_node.args->ForceSetArg("-bind", strprintf("3.4.5.6:%u", bind_port));
    m_node.args->ForceSetArg("-capturemessages", "1");

    // Our address:port as seen from the peer - 2.3.4.5:20002 (different from the above).
    in_addr peer_us_addr;
    peer_us_addr.s_addr = htonl(0x02030405);
    const CService peer_us{peer_us_addr, 20002};

    // Create a peer with a routable IPv4 address.
    in_addr peer_in_addr;
    peer_in_addr.s_addr = htonl(0x01020304);
    CNode peer{/*id=*/0,
               /*sock=*/nullptr,
               /*addrIn=*/CAddress{CService{peer_in_addr, 8333}, NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0,
               /*nLocalHostNonceIn=*/0,
               /*addrBindIn=*/CAddress{},
               /*addrNameIn=*/std::string{},
               /*conn_type_in=*/ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false};

    const uint64_t services{NODE_NETWORK | NODE_WITNESS};
    const int64_t time{0};
    const CNetMsgMaker msg_maker{PROTOCOL_VERSION};

    // Force Chainstate::IsInitialBlockDownload() to return false.
    // Otherwise PushAddress() isn't called by PeerManager::ProcessMessage().
    TestChainState& chainstate =
        *static_cast<TestChainState*>(&m_node.chainman->ActiveChainstate());
    chainstate.JumpOutOfIbd();

    m_node.peerman->InitializeNode(peer, NODE_NETWORK);

    std::atomic<bool> interrupt_dummy{false};
    std::chrono::microseconds time_received_dummy{0};

    const auto msg_version =
        msg_maker.Make(NetMsgType::VERSION, PROTOCOL_VERSION, services, time, services, peer_us);
    CDataStream msg_version_stream{msg_version.data, SER_NETWORK, PROTOCOL_VERSION};

    m_node.peerman->ProcessMessage(
        peer, NetMsgType::VERSION, msg_version_stream, time_received_dummy, interrupt_dummy);

    const auto msg_verack = msg_maker.Make(NetMsgType::VERACK);
    CDataStream msg_verack_stream{msg_verack.data, SER_NETWORK, PROTOCOL_VERSION};

    // Will set peer.fSuccessfullyConnected to true (necessary in SendMessages()).
    m_node.peerman->ProcessMessage(
        peer, NetMsgType::VERACK, msg_verack_stream, time_received_dummy, interrupt_dummy);

    // Ensure that peer_us_addr:bind_port is sent to the peer.
    const CService expected{peer_us_addr, bind_port};
    bool sent{false};

    const auto CaptureMessageOrig = CaptureMessage;
    CaptureMessage = [&sent, &expected](const CAddress& addr,
                                        const std::string& msg_type,
                                        Span<const unsigned char> data,
                                        bool is_incoming) -> void {
        if (!is_incoming && msg_type == "addr") {
            CDataStream s(data, SER_NETWORK, PROTOCOL_VERSION);
            std::vector<CAddress> addresses;

            s >> addresses;

            for (const auto& addr : addresses) {
                if (addr == expected) {
                    sent = true;
                    return;
                }
            }
        }
    };

    m_node.peerman->SendMessages(&peer);

    BOOST_CHECK(sent);

    CaptureMessage = CaptureMessageOrig;
    chainstate.ResetIbd();
    m_node.args->ForceSetArg("-capturemessages", "0");
    m_node.args->ForceSetArg("-bind", "");
    // PeerManager::ProcessMessage() calls AddTimeData() which changes the internal state
    // in timedata.cpp and later confuses the test "timedata_tests/addtimedata". Thus reset
    // that state as it was before our test was run.
    TestOnlyResetTimeData();
}

void message_serialize_deserialize_test(bool v2, const std::vector<CSerializedNetMsg>& test_msgs)
{
    // use keys with all zeros
    BIP324Key key_L, key_P;
    memset(key_L.data(), 1, BIP324_KEY_LEN);
    memset(key_P.data(), 2, BIP324_KEY_LEN);

    // construct the serializers
    std::unique_ptr<TransportSerializer> serializer;
    std::unique_ptr<TransportDeserializer> deserializer;

    if (v2) {
        serializer = std::make_unique<V2TransportSerializer>(V2TransportSerializer(key_L, key_P));
        deserializer = std::make_unique<V2TransportDeserializer>(V2TransportDeserializer((NodeId)0, key_L, key_P));
    } else {
        serializer = std::make_unique<V1TransportSerializer>(V1TransportSerializer());
        deserializer = std::make_unique<V1TransportDeserializer>(V1TransportDeserializer(Params(), (NodeId)0, SER_NETWORK, INIT_PROTO_VERSION));
    }
    // run 100 times through all messages with the same cipher suite instances
    for (unsigned int i = 0; i < 100; i++) {
        for (size_t msg_index = 0; msg_index < test_msgs.size(); msg_index++) {
            const CSerializedNetMsg& msg_orig = test_msgs[msg_index];
            // bypass the copy protection
            CSerializedNetMsg msg;
            msg.data = msg_orig.data;
            msg.m_type = msg_orig.m_type;

            std::vector<unsigned char> serialized_header;
            serializer->prepareForTransport(msg, serialized_header);

            // read two times
            //  first: read header
            size_t read_bytes{0};
            Span<const uint8_t> span_header(serialized_header.data(), serialized_header.size());
            if (serialized_header.size() > 0) read_bytes += deserializer->Read(span_header);
            //  second: read the encrypted payload (if required)
            Span<const uint8_t> span_msg(msg.data.data(), msg.data.size());
            if (msg.data.size() > 0) read_bytes += deserializer->Read(span_msg);
            if (msg.data.size() > read_bytes) {
                Span<const uint8_t> span_msg(msg.data.data() + read_bytes, msg.data.size() - read_bytes);
                read_bytes += deserializer->Read(span_msg);
            }
            // message must be complete
            BOOST_CHECK(deserializer->Complete());
            BOOST_CHECK_EQUAL(read_bytes, msg.data.size() + serialized_header.size());

            bool reject_message{true};
            bool disconnect{true};
            CNetMessage result{deserializer->GetMessage(GetTime<std::chrono::microseconds>(), reject_message, disconnect, {})};
            // The first v2 message is reject by V2TransportDeserializer as a placeholder for transport version messages
            BOOST_CHECK(!v2 || (i == 0 && msg_index == 0) || !reject_message);
            BOOST_CHECK(!disconnect);
            if (reject_message) continue;
            BOOST_CHECK_EQUAL(result.m_type, msg_orig.m_type);
            BOOST_CHECK_EQUAL(result.m_message_size, msg_orig.data.size());
            if (!msg_orig.data.empty()) {
                BOOST_CHECK_EQUAL(0, memcmp(result.m_recv.data(), msg_orig.data.data(), msg_orig.data.size()));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(net_v2)
{
    // create some messages where we perform serialization and deserialization
    std::vector<CSerializedNetMsg> test_msgs;
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERACK));
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERSION, PROTOCOL_VERSION, (int)NODE_NETWORK, 123, CAddress(CService(), NODE_NONE), CAddress(CService(), NODE_NONE), 123, "foobar", 500000, true));
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::PING, 123456));
    CDataStream stream(ParseHex("020000000001013107ca31e1950a9b44b75ce3e8f30127e4d823ed8add1263a1cc8adcc8e49164000000001716001487835ecf51ea0351ef266d216a7e7a3e74b84b4efeffffff02082268590000000017a9144a94391b99e672b03f56d3f60800ef28bc304c4f8700ca9a3b0000000017a9146d5df9e79f752e3c53fc468db89cafda4f7d00cb87024730440220677de5b11a5617d541ba06a1fa5921ab6b4509f8028b23f18ab8c01c5eb1fcfb02202fe382e6e87653f60ff157aeb3a18fc888736720f27ced546b0b77431edabdb0012102608c772598e9645933a86bcd662a3b939e02fb3e77966c9713db5648d5ba8a0006010000"), SER_NETWORK, PROTOCOL_VERSION);
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::TX, CTransaction(deserialize, stream)));
    std::vector<CInv> vInv;
    for (unsigned int i = 0; i < 1000; i++) {
        vInv.push_back(CInv(MSG_BLOCK, Params().GenesisBlock().GetHash()));
    }
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::INV, vInv));

    // add a dummy message
    std::string dummy;
    for (unsigned int i = 0; i < 100; i++) {
        dummy += "020000000001013107ca31e1950a9b44b75ce3e8f30127e4d823ed8add1263a1cc8adcc8e49164000000001716001487835ecf51ea0351ef266d216a7e7a3e74b84b4efeffffff02082268590000000017a9144a94391b99e672b03f56d3f60800ef28bc304c4f8700ca9a3b0000000017a9146d5df9e79f752e3c53fc468db89cafda4f7d00cb87024730440220677de5b11a5617d541ba06a1fa5921ab6b4509f8028b23f18ab8c01c5eb1fcfb02202fe382e6e87653f60ff157aeb3a18fc888736720f27ced546b0b77431edabdb0012102608c772598e9645933a86bcd662a3b939e02fb3e77966c9713db5648d5ba8a0006010000";
    }
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make("foobar", dummy));

    message_serialize_deserialize_test(true, test_msgs);
    message_serialize_deserialize_test(false, test_msgs);
}

BOOST_AUTO_TEST_CASE(bip324_derivation_test)
{
    // BIP324 key derivation uses network magic in the HKDF process. We use mainnet
    // params here to make it easier for other implementors to use this test as a test vector.
    SelectParams(CBaseChainParams::MAIN);
    static const std::string strSecret1 = "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj";
    static const std::string strSecret2C = "L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g";
    static const std::string initiator_ellswift_str = "b654960dff0ba8808a34337f46cc68ba7619c9df76d0550639dea62de07d17f9cb61b85f2897834ce12c50b1aefa281944abf2223a5fcf0a2a7d8c022498db35";
    static const std::string responder_ellswift_str = "ea57aae33e8dd38380c303fb561b741293ef97c780445184cabdb5ef207053db628f2765e5d770f666738112c94714991362f6643d9837e1c89cbd9710b80929";

    auto initiator_ellswift = ParseHex(initiator_ellswift_str);
    auto responder_ellswift = ParseHex(responder_ellswift_str);

    CKey initiator_key = DecodeSecret(strSecret1);
    CKey responder_key = DecodeSecret(strSecret2C);

    auto initiator_secret = initiator_key.ComputeBIP324ECDHSecret(MakeByteSpan(responder_ellswift), MakeByteSpan(initiator_ellswift), true);
    BOOST_CHECK(initiator_secret.has_value());
    auto responder_secret = responder_key.ComputeBIP324ECDHSecret(MakeByteSpan(initiator_ellswift), MakeByteSpan(responder_ellswift), false);
    BOOST_CHECK(responder_secret.has_value());
    BOOST_CHECK(initiator_secret.value() == responder_secret.value());
    BOOST_CHECK_EQUAL("85ac83c8b2cd328293d49b9ed999d9eff79847e767a6252dc17ae248b0040de0", HexStr(initiator_secret.value()));
    BOOST_CHECK_EQUAL("85ac83c8b2cd328293d49b9ed999d9eff79847e767a6252dc17ae248b0040de0", HexStr(responder_secret.value()));

    BIP324Session initiator_session, responder_session;

    DeriveBIP324Session(std::move(initiator_secret.value()), initiator_session);
    DeriveBIP324Session(std::move(responder_secret.value()), responder_session);

    BOOST_CHECK(initiator_session.initiator_L == responder_session.initiator_L);
    BOOST_CHECK_EQUAL("6bb300568ba8c0e19d78a0615854748ca675448e402480f3f260a8ccf808335a", HexStr(initiator_session.initiator_L));

    BOOST_CHECK(initiator_session.initiator_P == responder_session.initiator_P);
    BOOST_CHECK_EQUAL("128962f7dc651d92a9f4f4925bbf4a58f77624d80b9234171a9b7d1ab15f5c05", HexStr(initiator_session.initiator_P));

    BOOST_CHECK(initiator_session.responder_L == responder_session.responder_L);
    BOOST_CHECK_EQUAL("e3a471e934b306015cb33727ccdc3c458960792d48d2207e14b5b0b88fd464c2", HexStr(initiator_session.responder_L));

    BOOST_CHECK(initiator_session.responder_P == responder_session.responder_P);
    BOOST_CHECK_EQUAL("1b251c795df35bda9351f3b027834517974fc2a092b450e5bf99152ebf159746", HexStr(initiator_session.responder_P));

    BOOST_CHECK(initiator_session.session_id == responder_session.session_id);
    BOOST_CHECK_EQUAL("e7047d2a41c8f040ea7f278fbf03e40b40d70ed3d555b6edb163d91af518cf6b", HexStr(initiator_session.session_id));

    BOOST_CHECK(initiator_session.initiator_garbage_terminator == responder_session.initiator_garbage_terminator);
    BOOST_CHECK_EQUAL("00fdde2e0174d8abcfba3ed0c3d31600", HexStr(initiator_session.initiator_garbage_terminator));

    BOOST_CHECK(initiator_session.responder_garbage_terminator == responder_session.responder_garbage_terminator);
    BOOST_CHECK_EQUAL("6fad393127f7a80c23e5e08d203dfe3d", HexStr(initiator_session.responder_garbage_terminator));

    SelectParams(CBaseChainParams::REGTEST);
}

void assert_bip324_test_vector(uint16_t in_idx,
                               const std::string& in_priv_ours_hex,
                               const std::string& in_ellswift_ours_hex,
                               const std::string& in_ellswift_theirs_hex,
                               bool in_initiating,
                               const std::string& in_contents_hex,
                               uint32_t in_multiply,
                               const std::string& in_aad_hex,
                               bool in_ignore,
                               const std::string& mid_shared_secret_hex,
                               const std::string& mid_initiator_L_hex,
                               const std::string& mid_initiator_P_hex,
                               const std::string& mid_responder_L_hex,
                               const std::string& mid_responder_P_hex,
                               const std::string& out_session_id_hex,
                               const std::string& mid_send_garbage_terminator_hex,
                               const std::string& mid_recv_garbage_terminator_hex,
                               const std::string& out_ciphertext_hex,
                               const std::string& out_ciphertext_endswith_hex)
{
    auto parsed_hex = ParseHex(in_priv_ours_hex);

    CKey in_priv_ours;
    in_priv_ours.Set(parsed_hex.begin(), parsed_hex.end(), false);

    EllSwiftPubKey in_ellswift_ours, in_ellswift_theirs;

    parsed_hex = ParseHex(in_ellswift_ours_hex);
    memcpy(in_ellswift_ours.data(), parsed_hex.data(), parsed_hex.size());
    parsed_hex = ParseHex(in_ellswift_theirs_hex);
    memcpy(in_ellswift_theirs.data(), parsed_hex.data(), parsed_hex.size());

    std::vector<std::byte> in_contents;
    auto contents_bytes = ParseHex<std::byte>(in_contents_hex);
    for (size_t i = 0; i < in_multiply; i++) {
        std::copy(contents_bytes.begin(), contents_bytes.end(), std::back_inserter(in_contents));
    }

    auto in_aad = ParseHex<std::byte>(in_aad_hex);

    BIP324HeaderFlags flags{BIP324_NONE};
    if (in_ignore) {
        flags = BIP324_IGNORE;
    }

    auto shared_secret = in_priv_ours.ComputeBIP324ECDHSecret(in_ellswift_theirs,
                                                              in_ellswift_ours,
                                                              in_initiating);
    BOOST_CHECK_EQUAL(HexStr(shared_secret.value()), mid_shared_secret_hex);

    BIP324Session session;
    DeriveBIP324Session(std::move(shared_secret.value()), session);

    BOOST_CHECK_EQUAL(HexStr(session.initiator_L), mid_initiator_L_hex);
    BOOST_CHECK_EQUAL(HexStr(session.initiator_P), mid_initiator_P_hex);
    BOOST_CHECK_EQUAL(HexStr(session.responder_L), mid_responder_L_hex);
    BOOST_CHECK_EQUAL(HexStr(session.responder_P), mid_responder_P_hex);
    BOOST_CHECK_EQUAL(HexStr(session.session_id), out_session_id_hex);

    std::unique_ptr<BIP324CipherSuite> suite;
    if (in_initiating) {
        BOOST_CHECK_EQUAL(HexStr(session.initiator_garbage_terminator), mid_send_garbage_terminator_hex);
        BOOST_CHECK_EQUAL(HexStr(session.responder_garbage_terminator), mid_recv_garbage_terminator_hex);
        suite = std::make_unique<BIP324CipherSuite>(session.initiator_L, session.initiator_P);

    } else {
        BOOST_CHECK_EQUAL(HexStr(session.responder_garbage_terminator), mid_send_garbage_terminator_hex);
        BOOST_CHECK_EQUAL(HexStr(session.initiator_garbage_terminator), mid_recv_garbage_terminator_hex);
        suite = std::make_unique<BIP324CipherSuite>(session.responder_L, session.responder_P);
    }

    std::vector<std::byte> ciphertext(V2_MIN_PACKET_LENGTH + in_contents.size());
    std::array<std::byte, V2_MIN_PACKET_LENGTH> throwaway_ct;

    for (auto i = 0; i < in_idx; i++) {
        BOOST_CHECK(suite->Crypt({}, {}, throwaway_ct, flags, true));
    }

    BOOST_CHECK(suite->Crypt(in_aad, in_contents, ciphertext, flags, true));
    if (!out_ciphertext_hex.empty()) {
        BOOST_CHECK_EQUAL(HexStr(ciphertext), out_ciphertext_hex);
    }

    if (!out_ciphertext_endswith_hex.empty()) {
        auto ciphertext_endswith_hex = HexStr(
            MakeUCharSpan(ciphertext).last(out_ciphertext_endswith_hex.size() / 2));
        BOOST_CHECK_EQUAL(ciphertext_endswith_hex, out_ciphertext_endswith_hex);
    }
}


BOOST_AUTO_TEST_CASE(bip324_vectors_test)
{
    // BIP324 key derivation uses network magic in the HKDF derivation process.
    SelectParams(CBaseChainParams::MAIN);

    UniValue tests;
    tests.read((const char*)json_tests::bip324_vectors, sizeof(json_tests::bip324_vectors));
    for (const auto& vec : tests.getValues()) {
        assert_bip324_test_vector(
            vec["in_idx"].getInt<uint16_t>(),
            vec["in_priv_ours"].get_str(),
            vec["in_ellswift_ours"].get_str(),
            vec["in_ellswift_theirs"].get_str(),
            vec["in_initiating"].getInt<uint8_t>() == 0 ? false : true,
            vec["in_contents"].get_str(),
            vec["in_multiply"].getInt<uint32_t>(),
            vec["in_aad"].get_str(),
            vec["in_ignore"].getInt<uint8_t>() == 0 ? false : true,
            vec["mid_shared_secret"].get_str(),
            vec["mid_initiator_l"].get_str(),
            vec["mid_initiator_p"].get_str(),
            vec["mid_responder_l"].get_str(),
            vec["mid_responder_p"].get_str(),
            vec["out_session_id"].get_str(),
            vec["mid_send_garbage_terminator"].get_str(),
            vec["mid_recv_garbage_terminator"].get_str(),
            vec["out_ciphertext"].get_str(),
            vec["out_ciphertext_endswith"].get_str());
    }

    SelectParams(CBaseChainParams::REGTEST);
}
BOOST_AUTO_TEST_SUITE_END()
