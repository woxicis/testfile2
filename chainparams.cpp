// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2015-2017 The ALQO developers
// Copyright (c) 2017-2018 The MegaByteCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>


using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/*
#include "bignum.h"
void GenerateGenesisBlock(CBlock block)
{
	uint256 hashTarget = CBigNum().SetCompact(block.nBits).getuint256();
    uint256 thash;

    while (true)
    {
    	    thash = HashQuark(BEGIN(block.nVersion), END(block.nNonce));
        if (thash <= hashTarget)
            break;
        if ((block.nNonce & 0xFFF) == 0)
        {
            printf("nonce %08X: hash = %s (target = %s)\n", block.nNonce, thash.ToString().c_str(), hashTarget.ToString().c_str());
        }
        ++block.nNonce;
        if (block.nNonce == 0)
        {
            printf("NONCE WRAPPED, incrementing time\n");
            ++block.nTime;
        }
    }

    std::cout << block.ToString() << std::endl;
}

*/

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions

static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of(0, uint256("000008d6fa4fd5b127738655ca918f1fb3c5e5ebe7442838e17b49d0d6002b7f"));
static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
	1549553631, // * UNIX timestamp of last checkpoint block
    0,          // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
    2000        // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of(0, uint256("0x0"));
static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
	1549553631,
    0,
    250};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256("0x0"));
static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
	1549553631,
    0,
    100};

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0x70;
        pchMessageStart[1] = 0xAC;
        pchMessageStart[2] = 0x82;
        pchMessageStart[3] = 0x91;
        vAlertPubKey = ParseHex("048b3239ac13b8fd78ca70fd9536da0bf53598b2f91da36e0fc3075421e1f97bda0bed2336522c0dd575ac529ba8fbfd80e681f2a9b7217c2e98488adda7c15b76");
        nDefaultPort = 19662;
        bnProofOfWorkLimit = ~uint256(0) >> 20; // MegaByteCoin starting difficulty is 1 / 2^12  //20
        nSubsidyHalvingInterval = 210000;
        nMaxReorganizationDepth = 100;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 60; // MegaByteCoin: 1 minutes
        nTargetSpacing = 1 * 60;  // MegaByteCoin: 1 minute
        nLastPOWBlock = 300;
        nMaturity = 101;
        nMasternodeCountDrift = 20;
		nMasternodeColleteralLimxDev = 1000; //Params().MasternodeColleteralLimxDev()
        nModifierUpdateBlock = 1; // we use the version 2 for dmd
        nMaxMoneyOut = 21000000 * COIN;

        const char* pszTimestamp = "Bakkt Shares BTC Futures Details, Kucoin Adds Grin Trading Pairs";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 500 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("02d59c02ddfeab38230e2d5279a9e7868d2a5e662e7fba995ccbc270cb4b7420ea3d7bb7f4acaed0a8d9bf17e19194aeb8d4b50b30c01fd8e65584ec3435828cd7") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime = 1549553631;
        genesis.nBits = 0x1e0ffff0;
        genesis.nNonce = 21191344;

        //GenerateGenesisBlock(genesis);
        /*
        CBlock(hash=0000005fb5bc70df5d3f470497fbf5ec34606df0ca5ca6157424a441cfaa9329, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=03c8762ec4b0597a4437f8fafb7046a718f9f1089aabf9b06ba9560d105febfc, nTime=1519010250, nBits=1e00fff0, nNonce=121211724, vtx=1)
          CTransaction(hash=03c8762ec4, ver=1, vin.size=1, vout.size=1, nLockTime=0)
            CTxIn(COutPoint(0000000000000000000000000000000000000000000000000000000000000000, 4294967295), coinbase 04ffff001d01043a466562727561727920313874682c2032303138202d20537769747a65726c616e6420656d6272616365732063727970746f63757272656e63792e)
            CTxOut(nValue=0.00000000, scriptPubKey=040fbf75ea45bf7eb65f9075e8342b)
        */

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("000008d6fa4fd5b127738655ca918f1fb3c5e5ebe7442838e17b49d0d6002b7f"));
        assert(genesis.hashMerkleRoot == uint256("7aa93ffce9359ebdbe98bc696ac2fe9f99a68658871a9841ab82605ca625a957"));

	vFixedSeeds.clear();
        vSeeds.clear();


/*
        vSeeds.push_back(CDNSSeedData("45.32.154.101", "45.32.154.101"));         // Single node address
        vSeeds.push_back(CDNSSeedData("45.76.87.39", "45.76.87.39"));           // Single node address
        vSeeds.push_back(CDNSSeedData("45.77.55.100", "45.77.55.100"));         // Single node address
        vSeeds.push_back(CDNSSeedData("104.238.159.71", "104.238.159.71"));         // Single node address
		vSeeds.push_back(CDNSSeedData("37.143.8.42", "37.143.8.42"));         // Single node address
*/
		
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 110);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 16);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 193);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        // 	BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md 1977 0x800007b9
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x07)(0xb9).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        fHeadersFirstSyncingActive = false;

        nPoolMaxTransactions = 3;
        strSporkKey = "0426d6ef1fd84e4e41c4dac9a2cd8ce0eb616cbc9c407e95749be151b2f37ea4c18535d54ca6d5c29d6d9d3ae5f666eaed86f51a1498c6abb1284e43bb5cd477d8";
        strDarksendPoolDummyAddress = "McmpqXViWUXNroqVNYRdKjKrFM6PNa1oTM";
        nStartMasternodePayments = 1519010250;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0x64;
        pchMessageStart[1] = 0x44;
        pchMessageStart[2] = 0x65;
        pchMessageStart[3] = 0x54;
        vAlertPubKey = ParseHex("0447add5c60a37b9363bb1cee0700ea034deadb5b8c74a60e3b3dc64df8d55a74dce43ffd7710bf332bd7625ea89a3f238d37853c2606c668460dd394c4281e5f3");
        nDefaultPort = 20777;
        nEnforceBlockUpgradeMajority = 51;
        nRejectBlockOutdatedMajority = 75;
        nToCheckBlockUpgradeMajority = 100;
        nMinerThreads = 0;
        nTargetTimespan = 10; // MegaByteCoin: 10 seconds
        nTargetSpacing = 10;  // MegaByteCoin: 10 seconds
        nLastPOWBlock = 200;
        nMaturity = 15;
        nModifierUpdateBlock = 51197; //approx Mon, 17 Apr 2017 04:00:00 GMT
        nMaxMoneyOut = 100000000 * COIN;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1549553631;
        genesis.nNonce = 21191344;

        //GenerateGenesisBlock(genesis);
        /*
        CBlock(hash=0000008d766907f5113186ac3e9f198d8d2d96987e6b4a1fc65723050366d94b, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=03c8762ec4b0597a4437f8fafb7046a718f9f1089aabf9b06ba9560d105febfc, nTime=1519010251, nBits=1e00fff0, nNonce=20767169, vtx=1)
          CTransaction(hash=03c8762ec4, ver=1, vin.size=1, vout.size=1, nLockTime=0)
            CTxIn(COutPoint(0000000000000000000000000000000000000000000000000000000000000000, 4294967295), coinbase 04ffff001d01043a466562727561727920313874682c2032303138202d20537769747a65726c616e6420656d6272616365732063727970746f63757272656e63792e)
            CTxOut(nValue=0.00000000, scriptPubKey=040fbf75ea45bf7eb65f9075e8342b)
        */

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("000008d6fa4fd5b127738655ca918f1fb3c5e5ebe7442838e17b49d0d6002b7f"));

        vFixedSeeds.clear();
        vSeeds.clear();
/*
        vSeeds.push_back(CDNSSeedData("80.211.128.125", "80.211.128.125"));         // Single node address
        vSeeds.push_back(CDNSSeedData("94.177.187.54", "94.177.187.54"));           // Single node address
        vSeeds.push_back(CDNSSeedData("80.211.129.187", "80.211.129.187"));         // Single node address
*/

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 65);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 18);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 193);
        // Testnet MegaByteCoin BIP32 pubkeys start with 'DRKV'
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x3a)(0x80)(0x61)(0xa0).convert_to_container<std::vector<unsigned char> >();
        // Testnet MegaByteCoin BIP32 prvkeys start with 'DRKP'
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x3a)(0x80)(0x58)(0x37).convert_to_container<std::vector<unsigned char> >();
        // Testnet MegaByteCoin BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 2;
        strSporkKey = "04cf8cf091452a4055db448ef4cb46613bb3590ba32d74038ae4f23b82e2e6709c3f9b71682338380dedc82bc2a40c99dbd236b1da23dba04b15094f71a8aeb0e5";
        strDarksendPoolDummyAddress = "";
        nStartMasternodePayments = 1519010250;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        pchMessageStart[0] = 0x14;
        pchMessageStart[1] = 0x54;
        pchMessageStart[2] = 0x95;
        pchMessageStart[3] = 0x64;
        nDefaultPort = 21777;
        nSubsidyHalvingInterval = 150;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        nTargetTimespan = 5 * 60; // MegaByteCoin: 5 minutes
        nTargetSpacing = 1 * 60;  // MegaByteCoin: 1 minute
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        genesis.nTime = 1549553631;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 20542304;

        //GenerateGenesisBlock(genesis);
        /*
        CBlock(hash=00000049606f05027a9c1035dbc85f068122b03085c4766389fb69e71508f23e, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=03c8762ec4b0597a4437f8fafb7046a718f9f1089aabf9b06ba9560d105febfc, nTime=1519010252, nBits=1e00fff0, nNonce=14592436, vtx=1)
          CTransaction(hash=03c8762ec4, ver=1, vin.size=1, vout.size=1, nLockTime=0)
            CTxIn(COutPoint(0000000000000000000000000000000000000000000000000000000000000000, 4294967295), coinbase 04ffff001d01043a466562727561727920313874682c2032303138202d20537769747a65726c616e6420656d6272616365732063727970746f63757272656e63792e)
            CTxOut(nValue=0.00000000, scriptPubKey=040fbf75ea45bf7eb65f9075e8342b)
        */

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("021ed52060642cf3868084eb7af6212b02e0fd2f1b2dc3272f3b561149856e2e"));

        vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams
{
public:
    CUnitTestParams()
    {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 21777;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Unit test mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval) { nSubsidyHalvingInterval = anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority) { nEnforceBlockUpgradeMajority = anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority) { nRejectBlockOutdatedMajority = anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority) { nToCheckBlockUpgradeMajority = anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks) { fDefaultConsistencyChecks = afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) { fAllowMinDifficultyBlocks = afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams* pCurrentParams = 0;

CModifiableParams* ModifiableParams()
{
    assert(pCurrentParams);
    assert(pCurrentParams == &unitTestParams);
    return (CModifiableParams*)&unitTestParams;
}

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    case CBaseChainParams::UNITTEST:
        return unitTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
