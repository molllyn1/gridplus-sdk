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
const seedrandom = require('seedrandom');
const prng = new seedrandom(process.env.SEED || 'myrandomseed');
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

function randInt(n) {
  return Math.floor(n * prng.quick());
}

function buildIterLabels() {
  for (let i = 0; i < numRandom; i++)
    randomTxDataLabels.push({ label: `${i+1}/${numRandom}`, number: i })
}

// Test boundaries for chainId sizes. We allow chainIds up to MAX_UINT64, but
// the mechanism to test is different for chainIds >254.
// NOTE: All unknown chainIds lead to using EIP155 (which includes all of these)
function getChainId(pow, add) {
  return `0x${new BN(2).pow(pow).plus(add).toString(16)}`
}

function getFakeChain() {
  return {
    'name': 'myFakeChain',
    'chainId': 0,
    'networkId': 0,
    'genesis': {},
    'hardforks': [],
    'bootstrapNodes': [],
  };
}

function buildRandomTxData(fwConstants) {
  const maxDataSz = fwConstants.ethMaxDataSz + (fwConstants.extraDataMaxFrames * fwConstants.extraDataFrameSz);
  for (let i = 0; i < numRandom; i++) {
    const tx = {
      nonce: randInt(16000),
      gasPrice: ETH_GAS_PRICE_MIN + randInt(ETH_GAS_PRICE_MAX - ETH_GAS_PRICE_MIN),
      gasLimit: ETH_GAS_LIMIT_MIN + randInt(ETH_GAS_LIMIT_MAX - ETH_GAS_LIMIT_MIN),
      value: randInt(10**randInt(30)),
      to: `0x${crypto.randomBytes(20).toString('hex')}`,
      data: `0x${crypto.randomBytes(randInt(maxDataSz)).toString('hex')}`,
      eip155: randInt(2) > 0 ? true : false,
      // 51 is the max bit size that we can validate with our bignum lib (see chainID section)
      _network: getChainId(randInt(52), 0), 
    }
    randomTxData.push(tx);
  }
}

function buildRandomMsg(type='signPersonal') {
  if (type === 'signPersonal') {
    // A random string will do
    const isHexStr = randInt(2) > 0 ? true : false;
    const fwConstants = constants.getFwVersionConst(client.fwVersion);
    const L = randInt(fwConstants.ethMaxDataSz - MSG_PAYLOAD_METADATA_SZ);
    if (isHexStr)
      return `0x${crypto.randomBytes(L).toString('hex')}`; // Get L hex bytes (represented with a string with 2*L chars)
    else
      return randomWords({ exactly: L, join: ' ' }).slice(0, L); // Get L ASCII characters (bytes)
  } else if (type === 'eip712') {
    return helpers.buildRandomEip712Object(randInt);
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
    buildRandomTxData(fwConstants);
  });
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
      txData.data = `0x${crypto.randomBytes(randInt(100)).toString('hex')}`;

      // Custom chains need to be fully defined for EthereumJS's Common module
      // Here we just define a dummy chain. It isn't used for anything, but is required
      // for us to verify the output transaction payload against EthereumJS-TX (reference impl)
      const chain = getFakeChain();

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
      chain.chainId = chain.networkId = getChainId(51, 0); // 8 byte id
      // 8 bytes for the id itself and 1 byte for chainIdSz. This data is serialized into the request payload.
      let chainIdSz = 9;
      const fwConstants = constants.getFwVersionConst(client.fwVersion);
      const maxDataSz = fwConstants.ethMaxDataSz + (fwConstants.extraDataMaxFrames * fwConstants.extraDataFrameSz);
      txData.data = `0x${crypto.randomBytes(maxDataSz - chainIdSz).toString('hex')}`;
      await testTxPass(buildTxReq(txData, chain.chainId), chain);
      txData.data = `0x${crypto.randomBytes(maxDataSz - chainIdSz + 1).toString('hex')}`;
      await testTxFail(buildTxReq(txData, chain.chainId), chain);
      // Also test smaller sizes
      chain.chainId = chain.networkId = getChainId(16, -1);
      chainIdSz = 3;
      txData.data = `0x${crypto.randomBytes(maxDataSz - chainIdSz).toString('hex')}`;
      await testTxPass(buildTxReq(txData, chain.chainId), chain);
      txData.data = `0x${crypto.randomBytes(maxDataSz - chainIdSz + 1).toString('hex')}`;
      await testTxFail(buildTxReq(txData, chain.chainId), chain);

    })

    it('Should test range of `value`', async () => {
      const txData = JSON.parse(JSON.stringify(defaultTxData))
      txData.value = 1;
      await testTxPass(buildTxReq(txData))
      txData.value = 1234;
      await testTxPass(buildTxReq(txData))
      txData.value = `0x${new BN('10e14').toString(16)}`;
      await testTxPass(buildTxReq(txData))
      txData.value = `0x${new BN('10e64').toString(16)}`;
      await testTxPass(buildTxReq(txData))      
      txData.value = `0x${new BN('1e77').minus(1).toString(16)}`;
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
      const maxDataSz = fwConstants.ethMaxDataSz + (fwConstants.extraDataMaxFrames * fwConstants.extraDataFrameSz);

      txData.data = buildDataStr(1, maxDataSz - 1)
      await testTxPass(buildTxReq(txData))
      txData.data = buildDataStr(2, maxDataSz)  
      await testTxPass(buildTxReq(txData))

      // Expected failures
      txData.data = buildDataStr(3, maxDataSz + 1)
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
*/
/*
describe('Test random transaction data', function() {
  beforeEach(() => {
    expect(foundError).to.equal(false, 'Error found in prior test. Aborting.');
  })

  it.each(randomTxDataLabels, 'Random transactions %s', ['label'], async function(n, next) {
    const txData = randomTxData[n.number];
    const chain = getFakeChain();
    chain.chainId = chain.networkId = txData._network
    try {
      await testTxPass(buildTxReq(txData, chain.chainId), chain)
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

  it('Should throw error when message contains non-ASCII characters', async () => {
    const protocol = 'signPersonal';
    const msg = '⚠️';
    const msg2 = 'ASCII plus ⚠️';
    await testMsg(buildMsgReq(msg, protocol), false);
    await testMsg(buildMsgReq(msg2, protocol), false);
  })

  it('Should test ASCII buffers', async () => {
    await testMsg(buildMsgReq(Buffer.from('i am an ascii buffer'), 'signPersonal'), true);
    await testMsg(buildMsgReq(Buffer.from('{\n\ttest: foo\n}'), 'signPersonal'), false);
  })

  it('Should test hex buffers', async () => {
    await testMsg(buildMsgReq(Buffer.from('abcdef', 'hex'), 'signPersonal'), true);
  })

  it('Msg: sign_personal boundary conditions', async () => {
    const protocol = 'signPersonal';
    const fwConstants = constants.getFwVersionConst(client.fwVersion);
    const maxMsgSz = fwConstants.ethMaxMsgSz + (fwConstants.extraDataMaxFrames * fwConstants.extraDataFrameSz);
    const maxValid = `0x${crypto.randomBytes(maxMsgSz).toString('hex')}`;
    const minInvalid = `0x${crypto.randomBytes(maxMsgSz + 1).toString('hex')}`;
    const zeroInvalid = '0x';
    await testMsg(buildMsgReq(maxValid, protocol), true);
    await testMsg(buildMsgReq(minInvalid, protocol), false);
    await testMsg(buildMsgReq(zeroInvalid, protocol), false);
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

})
*/

describe('Test ETH EIP712', function() {
/*
  it('Should test canonical EIP712 example', async () => {
    const msg = {
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
    const req = {
      currency: 'ETH_MSG',
      data: {
        signerPath: [helpers.BTC_LEGACY_PURPOSE, helpers.ETH_COIN, HARDENED_OFFSET, 0, 0],
        protocol: 'eip712',
        payload: msg,
      }
    }
    try {
      await helpers.sign(client, req);
    } catch (err) {
      expect(err).to.equal(null)
    }
  })

  it('Should test canonical EIP712 example with 2nd level nesting', async () => {
    const msg = {
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' }
        ],
        Wallet: [
          { name: 'address', type: 'address' },
          { name: 'balance', type: 'uint256' },
        ],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'Wallet' }
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
          wallet: {
            address: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
            balance: '0x12345678',
          },
        },
        to: {
          name: 'Bob',
          wallet: {
            address: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
            balance: '0xabcdef12'
          },
        },
        contents: 'foobar'
      }
    };
    const req = {
      currency: 'ETH_MSG',
      data: {
        signerPath: [helpers.BTC_LEGACY_PURPOSE, helpers.ETH_COIN, HARDENED_OFFSET, 0, 0],
        protocol: 'eip712',
        payload: msg,
      }
    }
    try {
      await helpers.sign(client, req);
    } catch (err) {
      expect(err).to.equal(null)
    }
  })

  it('Should test canonical EIP712 example with 3rd level nesting', async () => {
    const msg = {
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' }
        ],
        Qasset: [
          { name: 'foo', type: 'bool' },
        ],
        Wallet: [
          { name: 'address', type: 'address' },
          { name: 'balance', type: 'Balance' },
        ],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'Wallet' }
        ],
        Mail: [
          { name: 'asset', type: 'Qasset' },
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
        Balance: [
          { name: 'value', type: 'uint256' },
          { name: 'currency', type: 'string' }
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
        asset: {
          foo: true
        },
        from: {
          name: 'Cow',
          wallet: {
            address: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
            balance: {
              value: '0x12345678',
              currency: 'ETH',
            }
          },
        },
        to: {
          name: 'Bob',
          wallet: {
            address: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
            balance: {
              value: '0xabcdef12',
              currency: 'UNI',
            },
          },
        },
        contents: 'foobar'
      }
    };
    const req = {
      currency: 'ETH_MSG',
      data: {
        signerPath: [helpers.BTC_LEGACY_PURPOSE, helpers.ETH_COIN, HARDENED_OFFSET, 0, 0],
        protocol: 'eip712',
        payload: msg,
      }
    }
    try {
      await helpers.sign(client, req);
    } catch (err) {
      expect(err).to.equal(null)
    }
  })
 
  it('Should test canonical EIP712 example with 3rd level nesting and params in a different order', async () => {
    const msg = {
      types: {
        Balance: [
          { name: 'value', type: 'uint256' },
          { name: 'currency', type: 'string' }
        ],
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' }
        ],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'Wallet' }
        ],
        Wallet: [
          { name: 'address', type: 'address' },
          { name: 'balance', type: 'Balance' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' }
        ],
      },
      primaryType: 'Mail',
      domain: {
        name: 'Ether Mail',
        version: '1',
        chainId: 12,
        verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC'
      },
      message: {
        contents: 'foobar',
        from: {
          name: 'Cow',
          wallet: {
            address: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
            balance: {
              value: '0x12345678',
              currency: 'ETH',
            }
          },
        },
        to: {
          name: 'Bob',
          wallet: {
            address: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
            balance: {
              value: '0xabcdef12',
              currency: 'UNI',
            },
          },
        },
      }
    };
    const req = {
      currency: 'ETH_MSG',
      data: {
        signerPath: [helpers.BTC_LEGACY_PURPOSE, helpers.ETH_COIN, HARDENED_OFFSET, 0, 0],
        protocol: 'eip712',
        payload: msg,
      }
    }
    try {
      await helpers.sign(client, req);
    } catch (err) {
      expect(err).to.equal(null)
    }
  })

  it('Should test a bunch of EIP712 data types', async () => {
    const msg = {
      types: {
        EIP712Domain: [
          {
            name: 'name',
            type: 'string'
          },
          {
            name: 'version',
            type: 'string'
          },
          {
            name: 'chainId',
            type: 'uint256'
          },
          {
            name: 'verifyingContract',
            type: 'address'
          }
        ],
        PrimaryStuff: [
          { name: 'UINT8', type: 'uint8' },
          { name: 'UINT16', type: 'uint16' },
          { name: 'UINT32', type: 'uint32' },
          { name: 'UINT64', type: 'uint64' },
          { name: 'UINT256', type: 'uint256' },
          { name: 'BYTES1', type: 'bytes1' },
          { name: 'BYTES5', type: 'bytes5' },
          { name: 'BYTES7', type: 'bytes7' },
          { name: 'BYTES12', type: 'bytes12' },
          { name: 'BYTES16', type: 'bytes16' },
          { name: 'BYTES20', type: 'bytes20' },
          { name: 'BYTES21', type: 'bytes21' },
          { name: 'BYTES31', type: 'bytes31' },
          { name: 'BYTES32', type: 'bytes32' },
          { name: 'BYTES', type: 'bytes' },
          { name: 'STRING', type: 'string' },
          { name: 'BOOL', type: 'bool' },
          { name: 'ADDRESS', type: 'address' }
        ],
      },
      primaryType: 'PrimaryStuff',
      domain: {
        name: 'Muh Domainz',
        version: '1',
        chainId: 270,
        verifyingContract: '0xcc9c93cef8c70a7b46e32b3635d1a746ee0ec5b4'
      },
      'message': {
        UINT8: '0xab',
        UINT16: '0xb1d7',
        UINT32: '0x80bb335b',
        UINT64: '0x259528d5bc',
        UINT256: '0xad2693f24ba507750d1763ebae3661c07504',
        BYTES1: '0x2f',
        BYTES5: '0x9485269fa5',
        BYTES7: '0xc4e8d65ce8c3cf',
        BYTES12: '0x358eb7b28e8e1643e7c4737f',
        BYTES16: '0x7ace034ab088fdd434f1e817f32171a0',
        BYTES20: '0x4ab51f2d5bfdc0f1b96f83358d5f356c98583573',
        BYTES21: '0x6ecdc19b30c7fa712ba334458d77377b6a586bbab5',
        BYTES31: '0x06c21824a98643f96643b3220962f441210b007f4c19dfdf0dea53d097fc28',
        BYTES32: '0x59cfcbf35256451756b02fa644d3d0748bd98f5904febf3433e6df19b4df7452',
        BYTES: '0x0354b2c449772905b2598a93f5da69962f0444e0a6e2429e8f844f1011446f6fe81815846fb6ebe2d213968d1f8532749735f5702f565db0429b2fe596d295d9c06241389fe97fb2f3b91e1e0f2d978fb26e366737451f1193097bd0a2332e0bfc0cdb631005',
        STRING: 'I am a string hello there human',
        BOOL: true,
        ADDRESS: '0x078a8d6eba928e7ea787ed48f71c5936aed4625d',
      }
    }
    const req = {
      currency: 'ETH_MSG',
      data: {
        signerPath: [helpers.BTC_LEGACY_PURPOSE, helpers.ETH_COIN, HARDENED_OFFSET, 0, 0],
        protocol: 'eip712',
        payload: msg,
      }
    }
    try {
      await helpers.sign(client, req);
    } catch (err) {
      expect(err).to.equal(null)
    }
  })

  it('Should test a payload with multiple custom types', async () => {
    const payload = {
      'types': {
        'EIP712Domain': [
          {
            'name': 'name',
            'type': 'string'
          },
          {
            'name': 'version',
            'type': 'string'
          },
          {
            'name': 'chainId',
            'type': 'uint256'
          },
          {
            'name': 'verifyingContract',
            'type': 'address'
          }
        ],
        'Primary_Cave': [
          {
            'name': 'scientific',
            'type': 'Program'
          },
          {
            'name': 'he',
            'type': 'Father'
          },
        ],
        'Program': [
          {
            'name': 'may',
            'type': 'bytes3'
          },
          {
            'name': 'aid',
            'type': 'string'
          }
        ],
        'Father': [
          {
            'name': 'surrounded',
            'type': 'bytes'
          },
          {
            'name': 'driven',
            'type': 'bytes2'
          }
        ],
      },
      'primaryType': 'Primary_Cave',
      'domain': {
        'name': 'Domain_Sent',
        'version': '1',
        'chainId': 270,
        'verifyingContract': '0xe2b818aa5a616be9cdc5c723def863e54405a241'
      },
      'message': {
        'scientific': {
          'may': '0x0349b8',
          'aid': 'discussion threw thing bowl'
        },
        'he': {
          'surrounded': '0x523437bad397ccea',
          'driven': '0x77d9'
        },
      }
    }
    try {
      await testMsg(buildMsgReq(payload, 'eip712'))
    } catch (err) {
      expect(err).to.equal(null)
    }
  })

  it('Should test a payload with nested custom types', async () => {
    const payload = {
      'types': {
        'EIP712Domain': [
          {
            'name': 'name',
            'type': 'string'
          },
          {
            'name': 'version',
            'type': 'string'
          },
          {
            'name': 'chainId',
            'type': 'uint256'
          },
          {
            'name': 'verifyingContract',
            'type': 'address'
          }
        ],
        'Primary_Cave': [
          {
            'name': 'scientific',
            'type': 'Program'
          },
        ],
        'Program': [
          {
            'name': 'may',
            'type': 'Father'
          },
          {
            'name': 'aid',
            'type': 'string'
          }
        ],
        'Father': [
          {
            'name': 'surrounded',
            'type': 'bytes'
          },
          {
            'name': 'driven',
            'type': 'bytes2'
          }
        ],
      },
      'primaryType': 'Primary_Cave',
      'domain': {
        'name': 'Domain_Sent',
        'version': '1',
        'chainId': 270,
        'verifyingContract': '0xe2b818aa5a616be9cdc5c723def863e54405a241'
      },
      'message': {
        'scientific': {
          'may': {
            'surrounded': '0x523437bad397ccea',
            'driven': '0x77d9'
          },
          'aid': 'discussion threw thing bowl'
        },
      }
    }
    try {
      await testMsg(buildMsgReq(payload, 'eip712'))
    } catch (err) {
      expect(err).to.equal(null)
    }
  })
*/


  // it.each(randomTxDataLabels, 'Msg: EIP712 #%s', ['label'], async function(n, next) {
  it('Should test debug thing', async() => {
    // const payload = buildRandomMsg('eip712');
//     const payload = {
//   "types": {
//     "EIP712Domain": [
//       {
//         "name": "name",
//         "type": "string"
//       },
//       {
//         "name": "version",
//         "type": "string"
//       },
//       {
//         "name": "chainId",
//         "type": "uint256"
//       },
//       {
//         "name": "verifyingContract",
//         "type": "address"
//       }
//     ],
//     "Fooain_Abandon_distance_esc": [
//       /*{
//         "name": "fun_blind_only_raw_g",
//         "type": "Fiscal_permit_ten_to"
//       },
//       {
//         "name": "demand_local_wave_ri",
//         "type": "Fever_scissors_boat_"
//       },
//       {
//         "name": "trust_chimney_social",
//         "type": "Menu_drama_soup_nut_"
//       },
//       {
//         "name": "student_document_spe",
//         "type": "bytes11"
//       },
//       */
//       {
//         "name": "picture_dove_fence_u",
//         "type": "uint32"
//       }
//     ],
//     /*
//     "Fiscal_permit_ten_to": [
//       {
//         "name": "amazing_tuition_civi",
//         "type": "bytes18"
//       }
//     ],
//     "Fever_scissors_boat_": [
//       {
//         "name": "net_hurt_lobster_wei",
//         "type": "bytes9"
//       }
//     ],
//     "Menu_drama_soup_nut_": [
//       {
//         "name": "allow_uniform_glad_p",
//         "type": "bytes24"
//       },
//       {
//         "name": "panel_balance_quantu",
//         "type": "bytes6"
//       }
//     ]
//     */
//   },
//   "primaryTypeFOOBARFIZZBUZZ": "Fooain_Abandon_distance_esc",
//   "domain": {
//     "name": "Domain_Abandon_distance_esc",
//     "version": "1",
//     "chainId": "0x2ded",
//     "verifyingContract": "0x43f98f3e5e935a1c15d05dd8c0dcdc17529cf931"
//   },
//   "message": {
//     // "fun_blind_only_raw_g": {
//     //   "amazing_tuition_civi": "0x1506400a8f76c86a1e93e69a04cae9d478c2",
//     // },
//     // "demand_local_wave_ri": {
//     //   "net_hurt_lobster_wei": "0x9c5a1790fc51f8aec7",
//     // },
//     // "trust_chimney_social": {
//     //   "allow_uniform_glad_p": "0x4506ce86aa2c627329c94b748ad5aab709ab7f4236ee7098",
//     //   "panel_balance_quantu": "0x32d32ae81a23",
//     // },
//     // "student_document_spe": "0xcaf3ede5568a5994595994",
//     "picture_dove_fence_u": 8861790
//   }
// }
    const payload = {
      "primaryTypeFOOBARFIZZBUZZ": "Fooain_Abandon_distance_esc"
    }

    try {
      await testMsg(buildMsgReq(payload, 'eip712'))
      // setTimeout(() => { next() }, 500);
      expect(true).to.equal(true)
    } catch (err) {
      console.log(JSON.stringify(payload, null, 2))
      // setTimeout(() => { next(err) }, 500);
      expect(true).to.equal(true)
    }
  })

})