// Tests for ETH transaction edge cases
// NOTE: You must run the following BEFORE executing these tests:
//
// 1. Pair with the device once. This will ask you for your deviceID, which will
//    act as a salt for your pairing:
//
//    env REUSE_KEY=1 npm run test
//
// 2. Connect with the same deviceID you specfied in 1:
//
//    env DEVICE_ID='<your_device_id>' npm test
//
// After you do the above, you can run this test with `npm run test-eth`
//
// NOTE: It is highly suggested that you set `AUTO_SIGN_DEV_ONLY=1` in the firmware
//        root CMakeLists.txt file (for dev units)
require('it-each')({ testPerIteration: true });
const BN = require('bignumber.js');
const randomWords = require('random-words');
const crypto = require('crypto');
const EthTx = require('ethereumjs-tx').Transaction;
const constants = require('./../src/constants')
const expect = require('chai').expect;
const helpers = require('./testUtil/helpers');
const HARDENED_OFFSET = constants.HARDENED_OFFSET;
let client = null;
let numRandom = 20; // Number of random tests to conduct
const randomTxData = [];
const randomTxDataLabels = [];
let ETH_GAS_PRICE_MAX;                  // value depends on firmware version
const ETH_GAS_LIMIT_MIN = 22000;        // Ether transfer (smallest op) is 22k gas
const ETH_GAS_LIMIT_MAX = 12500000;     // 10M is bigger than the block size
const ETH_GAS_PRICE_MIN = 1000000;      // 1,000,000 = 0.001 GWei - minimum
const MSG_PAYLOAD_METADATA_SZ = 28;     // Metadata that must go in ETH_MSG requests
const defaultTxData = {
  nonce: 0,
  gasPrice: 1200000000,
  gasLimit: 50000,
  to: '0xe242e54155b1abc71fc118065270cecaaf8b7768',
  value: 100,
  data: null
};

function buildIterLabels() {
  for (let i = 0; i < numRandom; i++)
    randomTxDataLabels.push({ label: `${i+1}/${numRandom}`, number: i })
}

function buildRandomTxData() {
  // Constants from firmware
  for (let i = 0; i < numRandom; i++) {
    const tx = {
      nonce: Math.floor(Math.random() * 16000),
      gasPrice: ETH_GAS_PRICE_MIN + Math.floor(Math.random() * (ETH_GAS_PRICE_MAX - ETH_GAS_PRICE_MIN)),
      gasLimit: ETH_GAS_LIMIT_MIN + Math.floor(Math.random() * (ETH_GAS_LIMIT_MAX - ETH_GAS_LIMIT_MIN)),
      value: Math.floor(Math.random() * 10**Math.floor(Math.random()*30)),
      to: `0x${crypto.randomBytes(20).toString('hex')}`,
      data: `0x${crypto.randomBytes(Math.floor(Math.random() * 100)).toString('hex')}`,
    }
    randomTxData.push(tx);
  }
}

function buildRandomMsg(type='signPersonal') {
  if (type === 'signPersonal') {
    // A random string will do
    const isHexStr = Math.random() > 0.5;
    const fwConstants = constants.getFwVersionConst(client.fwVersion);
    const L = Math.floor(Math.random() * (fwConstants.ethMaxDataSz - MSG_PAYLOAD_METADATA_SZ));
    if (isHexStr)
      return `0x${crypto.randomBytes(L).toString('hex')}`; // Get L hex bytes (represented with a string with 2*L chars)
    else
      return randomWords({ exactly: L, join: ' ' }).slice(0, L); // Get L ASCII characters (bytes)
  }
}

function buildTxReq(txData, network='mainnet') {
  return {
    currency: 'ETH',
    data: {
      signerPath: [helpers.BTC_LEGACY_PURPOSE, helpers.ETH_COIN, HARDENED_OFFSET, 0, 0],
      ...txData,
      chainId: network
    }
  }
}

function buildMsgReq(payload, protocol) {
  return {
    currency: 'ETH_MSG',
    data: {
      signerPath: [helpers.BTC_LEGACY_PURPOSE, helpers.ETH_COIN, HARDENED_OFFSET, 0, 0],
      payload,
      protocol,
    }
  }
}

let foundError = false;

async function testTxPass(req, chain=null) {
  const tx = await helpers.sign(client, req);
  // Make sure there is transaction data returned
  // (this is ready for broadcast)
  const txIsNull = tx.tx === null;
  if (txIsNull === true)
    foundError = true;
  expect(txIsNull).to.equal(false);
  // Check the transaction data against a reference implementation
  // (ethereumjs-tx)
  const txData = {
    ...req.data,
    v: `0x${tx.sig.v.toString('hex')}`,
    r: `0x${tx.sig.r}`,
    s: `0x${tx.sig.s}`,
  }
  // There is one test where we submit an address without the prefix
  if (txData.to.slice(0, 2) !== '0x')
    txData.to = `0x${txData.to}`
  if (chain === null)
    chain = req.data.chainId;
  const expectedTx = new EthTx(txData, { chain }).serialize()
  const expectedTxStr = `0x${expectedTx.toString('hex')}`;
  if (tx.tx !== expectedTxStr) {
    foundError = true;
    console.error('Invalid tx resp!', JSON.stringify(txData))
  }
  expect(tx.tx).to.equal(expectedTxStr);
  return tx
}

async function testTxFail(req) {
  try {
    const tx = await helpers.sign(client, req);
    expect(tx.tx).to.equal(null);
    foundError = true;
  } catch (err) {
    expect(err).to.not.equal(null);
  }
}

async function testMsg(req, pass=true) {
  try {
    const sig = await helpers.sign(client, req);
    // Validation happens already in the client
    if (pass === true)
      expect(sig.sig).to.not.equal(null);
    else
      expect(sig.sig).to.equal(null);
  } catch (err) {
    if (pass === true)
      expect(err).to.equal(null);
    else
      expect(err).to.not.equal(null);
  }
}

// Determine the number of random transactions we should build
if (process.env.N)
  numRandom = parseInt(process.env.N);
// Build the labels
buildIterLabels();

describe('Setup client', () => {
  it('Should setup the test client', () => {
    client = helpers.setupTestClient(process.env);
    expect(client).to.not.equal(null);
  })

  it('Should connect to a Lattice and make sure it is already paired.', async () => {
    // Again, we assume that if an `id` has already been set, we are paired
    // with the hardcoded privkey above.
    expect(process.env.DEVICE_ID).to.not.equal(null);
    const connectErr = await helpers.connect(client, process.env.DEVICE_ID);
    expect(connectErr).to.equal(null);
    expect(client.isPaired).to.equal(true);
    expect(client.hasActiveWallet()).to.equal(true);
    // Set the correct max gas price based on firmware version
    const fwConstants = constants.getFwVersionConst(client.fwVersion);
    ETH_GAS_PRICE_MAX = fwConstants.ethMaxGasPrice;
    // Build the random transactions
    buildRandomTxData();
  });

  it('TEST Should build a message', async () => {

    const typedData = {
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' }
        ],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' }
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' }
        ]
      },
      primaryType: 'Mail',
      domain: {
        name: 'Ether Mail',
        version: '1',
        chainId: 12,
        verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC'
      },
      message: {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826'
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB'
        },
        contents: 'foobar'
      }
    };


    // noname: this is my name
    // fooSub1: something
/*
    const typedData = {
      types: {
        FooSub: [ { name: 'fooSub1', type: 'string' }],
        Foo: [ { name: 'noname', type: 'string' }, { name: 'something', type: 'FooSub' } ]
      },
      message: {
        noname: 'this is my name',
        something: {
          fooSub1: 'my sub'
        }
      },
      primaryType: 'Foo',
    };
*/
    const req = {
      currency: 'ETH_MSG',
      data: {
        signerPath: [helpers.BTC_LEGACY_PURPOSE, helpers.ETH_COIN, HARDENED_OFFSET, 0, 0],
        protocol: 'signTyped',
        payload: typedData,
      }
    }
    try {
      let tx = await helpers.sign(client, req);
      console.log(tx)
    } catch (err) {
      console.error(err)
    }
  })
})
/*
if (!process.env.skip) {
  describe('Test ETH Tx Params', () => {
    beforeEach(() => {
      expect(foundError).to.equal(false, 'Error found in prior test. Aborting.');
      setTimeout(() => {}, 5000);
    })

    it('Should test range of chainId sizes and EIP155 tag', async () => {
      const txData = JSON.parse(JSON.stringify(defaultTxData));
      // Add some random data for good measure, since this will interact with the data buffer
      txData.data = `0x${crypto.randomBytes(Math.floor(Math.random() * 100)).toString('hex')}`;

      // Custom chains need to be fully defined for EthereumJS's Common module
      // Here we just define a dummy chain. It isn't used for anything, but is required
      // for us to verify the output transaction payload against EthereumJS-TX (reference impl)
      const chain = {
        'name': 'myFakeChain',
        'chainId': 0,
        'networkId': 0,
        'genesis': {},
        'hardforks': [],
        'bootstrapNodes': [],
      };

      // Test boundaries for chainId sizes. We allow chainIds up to MAX_UINT64, but
      // the mechanism to test is different for chainIds >254.
      // NOTE: All unknown chainIds lead to using EIP155 (which includes all of these)
      function getChainId(pow, add) {
        return `0x${new BN(2).pow(pow).plus(add).toString(16)}`
      }

      // This one can fit in the normal chainID u8
      chain.chainId = chain.networkId = getChainId(8, -2); // 254
      await testTxPass(buildTxReq(txData, chain.chainId), chain)

      // These will need to go in the `data` buffer field
      chain.chainId = chain.networkId = getChainId(8, -1); // 255
      await testTxPass(buildTxReq(txData, chain.chainId), chain);
      chain.chainId = chain.networkId = getChainId(8, 0); // 256
      await testTxPass(buildTxReq(txData, chain.chainId), chain);
      chain.chainId = chain.networkId = getChainId(16, -2);
      await testTxPass(buildTxReq(txData, chain.chainId), chain);
      chain.chainId = chain.networkId = getChainId(16, -1);
      await testTxPass(buildTxReq(txData, chain.chainId), chain);
      chain.chainId = chain.networkId = getChainId(16, 0);
      await testTxPass(buildTxReq(txData, chain.chainId), chain);
      chain.chainId = chain.networkId = getChainId(32, -2);
      await testTxPass(buildTxReq(txData, chain.chainId), chain);
      chain.chainId = chain.networkId = getChainId(32, -1);
      await testTxPass(buildTxReq(txData, chain.chainId), chain);
      chain.chainId = chain.networkId = getChainId(32, 0);
      await testTxPass(buildTxReq(txData, chain.chainId), chain);

      // Annoyingly, our reference implementation that is used to validate the full
      // response payload can only build bignums of max size 2**51, so that is as
      // far as we can validate the full payload here. This of course uses the full
      // 8 byte chainID buffer, so we can test that size here.
      chain.chainId = chain.networkId = getChainId(51, 0);
      await testTxPass(buildTxReq(txData, chain.chainId), chain);

      // Although we can't check the payload itself, we can still validate that chainIDs
      // >UINT64_MAX will fail internal checks.
      let res;
      chain.chainId = chain.networkId = getChainId(64, -1); // UINT64_MAX should pass
      res = await helpers.sign(client, buildTxReq(txData, chain.chainId));
      expect(res.tx).to.not.equal(null);
      chain.chainId = chain.networkId = getChainId(64, 0); // UINT64_MAX+1 should fail
      try {
        res = await helpers.sign(client, buildTxReq(txData, chain.chainId));
      } catch (err) {
        expect(typeof err).to.equal('string');
      }

      // Test out a numerical chainId as well
      const numChainId = 10000
      chain.chainId = chain.networkId = `0x${numChainId.toString(16)}`; // 0x2710
      await testTxPass(buildTxReq(txData, numChainId), chain);

      // Test boundary of new dataSz
      chain.chainId = chain.networkId = getChainId(51, 0); // UINT64_MAX should pass
      const fwConstants = constants.getFwVersionConst(client.fwVersion);
      const maxDataSz = fwConstants.ethMaxDataSz - 9; // Subtract 8 bytes for chainID and 1 byte for chainIdSz
      txData.data = `0x${crypto.randomBytes(Math.floor(Math.random() * maxDataSz)).toString('hex')}`;
      await testTxPass(buildTxReq(txData, chain.chainId), chain);
      txData.data = `0x${crypto.randomBytes(Math.floor(Math.random() * maxDataSz+1)).toString('hex')}`;
      await testTxFail(buildTxReq(txData, chain.chainId), chain);
    })

    it('Should test range of `value`', async () => {
      const txData = JSON.parse(JSON.stringify(defaultTxData))
      txData.value = 1;
      await testTxPass(buildTxReq(txData))
      txData.value = 1234;
      await testTxPass(buildTxReq(txData))
      txData.value = 10**14;
      await testTxPass(buildTxReq(txData))
      txData.value = 10**64;
      await testTxPass(buildTxReq(txData))
      txData.value = 10**77;
      await testTxPass(buildTxReq(txData))
      txData.value = '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
      await testTxPass(buildTxReq(txData))
    });

    it('Should test the range of `data`', async () => {
      const txData = JSON.parse(JSON.stringify(defaultTxData))

      // Expected passes
      txData.data = null;
      await testTxPass(buildTxReq(txData))
      txData.data = '0x';
      await testTxPass(buildTxReq(txData))
      txData.data = '0x12345678';
      await testTxPass(buildTxReq(txData))

      // Check upper limit
      function buildDataStr(x, n) {
        x = x < 256 ? x : 0;
        const xs = x.toString(16).length === 1 ? `0${x.toString(16)}` : x.toString(16);
        let s = '0x';
        for (let i = 0; i < n; i++)
          s += xs
        return s;
      }
      const fwConstants = constants.getFwVersionConst(client.fwVersion);
      txData.data = buildDataStr(1, fwConstants.ethMaxDataSz - 1)
      await testTxPass(buildTxReq(txData))
      txData.data = buildDataStr(2, fwConstants.ethMaxDataSz)  
      await testTxPass(buildTxReq(txData))

      // Expected failures
      txData.data = buildDataStr(3, fwConstants.ethMaxDataSz + 1)
      await testTxFail(buildTxReq(txData))
    });

    it('Should test the range of `gasPrice`', async () => {
      const txData = JSON.parse(JSON.stringify(defaultTxData));
      
      // Expected passes
      txData.gasPrice = ETH_GAS_PRICE_MIN;
      await testTxPass(buildTxReq(txData))
      txData.gasPrice = ETH_GAS_PRICE_MAX;
      await testTxPass(buildTxReq(txData))

      // Expected failures
      txData.gasPrice = 0;
      await testTxFail(buildTxReq(txData))
      txData.gasPrice = ETH_GAS_PRICE_MIN - 1;
      await testTxFail(buildTxReq(txData))
      txData.gasPrice = ETH_GAS_PRICE_MAX + 1;
      await testTxFail(buildTxReq(txData))
    });

    it('Should test the range of `gasLimit`', async () => {
      const txData = JSON.parse(JSON.stringify(defaultTxData));
      
      // Expected passes
      txData.gasLimit = ETH_GAS_LIMIT_MIN;
      await testTxPass(buildTxReq(txData))
      txData.gasLimit = ETH_GAS_LIMIT_MAX;
      await testTxPass(buildTxReq(txData))

      // Expected failures
      txData.gasLimit = 0;
      await testTxFail(buildTxReq(txData))
      txData.gasLimit = ETH_GAS_LIMIT_MIN - 1;
      await testTxFail(buildTxReq(txData))
      txData.gasLimit = ETH_GAS_LIMIT_MAX + 1;
      await testTxFail(buildTxReq(txData))
    });

    it('Should test the range of `to`', async () => {
      const txData = JSON.parse(JSON.stringify(defaultTxData));
      
      // Expected passes
      txData.to = '0xe242e54155b1abc71fc118065270cecaaf8b7768';
      await testTxPass(buildTxReq(txData))
      txData.to = 'e242e54155b1abc71fc118065270cecaaf8b7768';
      await testTxPass(buildTxReq(txData))

      // Expected failures
      txData.gasLimit = 0;
      await testTxFail(buildTxReq(txData))
      txData.gasLimit = 21999;
      await testTxFail(buildTxReq(txData))
      txData.gasLimit = 50000001;
      await testTxFail(buildTxReq(txData))
    });

    it('Should test the range of `nonce`', async () => {
      const txData = JSON.parse(JSON.stringify(defaultTxData));
      
      // Expected passes
      txData.nonce = 0;
      await testTxPass(buildTxReq(txData))
      txData.nonce = 4294967295;
      await testTxPass(buildTxReq(txData))
      
      // Expected failures
      txData.nonce = 4294967296;
      await testTxFail(buildTxReq(txData))
    });

    it('Should test EIP155', async () => {
      const txData = JSON.parse(JSON.stringify(defaultTxData));
      await testTxPass(buildTxReq(txData, 'rinkeby')) // Does NOT use EIP155
      await testTxPass(buildTxReq(txData, 'mainnet')) // Uses EIP155

      // Finally, make sure the `eip155` tag works. We will set it to false and
      // expect a result that does not include EIP155 in the payload.
      const chain = {
        'name': 'myFakeChain',
        'chainId': 0,
        'networkId': 0,
        'genesis': {},
        'hardforks': [],
        'bootstrapNodes': [],
      };      
      txData.eip155 = false;
      const numChainId = 10000;
      chain.chainId = chain.networkId = `0x${numChainId.toString(16)}`; // 0x2710
      await testTxPass(buildTxReq(txData, numChainId), chain);
      const res = await testTxPass(buildTxReq(txData, numChainId), chain);
      // For non-EIP155 transactions, we expect `v` to be 27 or 28
      expect(res.sig.v.toString('hex')).to.oneOf([(27).toString(16), (28).toString(16)])
    });

  });
}

describe('Test random transaction data', function() {
  beforeEach(() => {
    expect(foundError).to.equal(false, 'Error found in prior test. Aborting.');
  })

  it.each(randomTxDataLabels, 'Random transaction %s', ['label'], async function(n, next) {
    const txData = randomTxData[n.number];
    const r = Math.round(Math.random())
    const network = r === 1 ? 'rinkeby' : 'mainnet';
    try {
      await testTxPass(buildTxReq(txData, network))
      setTimeout(() => { next() }, 2500);
    } catch (err) {
      setTimeout(() => { next(err) }, 2500);
    }
  })
})

describe('Test ETH personalSign', function() {
  beforeEach(() => {
    expect(foundError).to.equal(false, 'Error found in prior test. Aborting.');
  })

  it.each(randomTxDataLabels, 'Msg: sign_personal #%s', ['label'], async function(n, next) {
    const protocol = 'signPersonal';
    const payload = buildRandomMsg(protocol);
    try {
      await testMsg(buildMsgReq(payload, protocol))
      setTimeout(() => { next() }, 2500);
    } catch (err) {
      setTimeout(() => { next(err) }, 2500);
    }
  })

  it('Should throw error when message contains non-ASCII characters', async () => {
    const protocol = 'signPersonal';
    const msg = '⚠️';
    const msg2 = 'ASCII plus ⚠️';
    await testMsg(buildMsgReq(msg, protocol), false);
    await testMsg(buildMsgReq(msg2, protocol), false);
  })

  it('Msg: sign_personal boundary conditions', async () => {
    const protocol = 'signPersonal';
    const fwConstants = constants.getFwVersionConst(client.fwVersion);
    const maxSz = fwConstants.ethMaxDataSz;
    const maxValid = `0x${crypto.randomBytes(maxSz).toString('hex')}`;
    const minInvalid = `0x${crypto.randomBytes(maxSz + 1).toString('hex')}`;
    const zeroInvalid = '0x';
    await testMsg(buildMsgReq(maxValid, protocol), true);
    await testMsg(buildMsgReq(minInvalid, protocol), false);
    await testMsg(buildMsgReq(zeroInvalid, protocol), false);
  })
})
*/