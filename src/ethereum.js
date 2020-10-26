// Utils for Ethereum transactions. This is effecitvely a shim of ethereumjs-util, which
// does not have browser (or, by proxy, React-Native) support.
const Buffer = require('buffer/').Buffer
const constants = require('./constants');
const keccak256 = require('js-sha3').keccak256;
const rlp = require('rlp-browser');
const secp256k1 = require('secp256k1');

exports.buildEthereumMsgRequest = function(input) {
  if (!input.payload || !input.protocol || !input.signerPath)
    throw new Error('You must provide `payload`, `signerPath`, and `protocol` arguments in the messsage request');
  const req = {
    schema: constants.signingSchema.ETH_MSG,
    payload: null,
    input, // Save the input for later
    msg: null, // Save the buffered message for later
  }

  try {
    switch (input.protocol) {
      case 'signPersonal':
        return buildPersonalSignRequest(req, input);
      case 'signTypedData':
        return buildSignTypedDataRequest(req, input);
      default:
        return { err: 'Unsupported protocol' }
    }
  } catch (err) {
    return { err: err.message }
  }
}

exports.validateEthereumMsgResponse = function(res, req) {
  const { signer, sig } = res;
  const { input, msg } = req;
  if (input.protocol === 'signPersonal') {
    const prefix = Buffer.from(
      `\u0019Ethereum Signed Message:\n${msg.length.toString()}`,
      'utf-8',
    );
    return addRecoveryParam(Buffer.concat([prefix, msg]), sig, signer)
  } else {
    throw new Error('Unsupported protocol');
  }
}

exports.buildEthereumTxRequest = function(data) {
  try {
    let { chainId=1 } = data;
    const { signerPath } = data;
    if (typeof chainId !== 'number') chainId = chainIds[chainId];
    if (!chainId) throw new Error('Unsupported chain name');
    else if (!signerPath || signerPath.length !== 5) throw new Error('Please provider full signer path (`signerPath`)')
    const useEIP155 = eip155[chainId];

    // Hack for metamask, which sends value=null for 0 ETH transactions
    if (!data.value)
      data.value = 0;
      
    //--------------
    // 1. BUILD THE RAW TX FOR FUTURE RLP ENCODING
    //--------------

    // Ensure all fields are 0x-prefixed hex strings
    const rawTx = [];
    // Build the transaction buffer array
    const nonceBytes = ensureHexBuffer(data.nonce);
    const gasPriceBytes = ensureHexBuffer(data.gasPrice);
    const gasLimitBytes = ensureHexBuffer(data.gasLimit);
    const toBytes = ensureHexBuffer(data.to);
    const valueBytes = ensureHexBuffer(data.value);
    const dataBytes = ensureHexBuffer(data.data);

    rawTx.push(nonceBytes);
    rawTx.push(gasPriceBytes);
    rawTx.push(gasLimitBytes);
    rawTx.push(toBytes);
    rawTx.push(valueBytes);
    rawTx.push(dataBytes);
    // Add empty v,r,s values
    if (useEIP155 === true) {
      rawTx.push(ensureHexBuffer(chainId)); // v
      rawTx.push(ensureHexBuffer(null));    // r
      rawTx.push(ensureHexBuffer(null));    // s
    }

    //--------------
    // 2. BUILD THE LATTICE REQUEST PAYLOAD
    //--------------

    // Here we take the data from the raw transaction and serialize it into a buffer that
    // can be consumed by the Lattice firmware. Note that each field has a 4-byte prefix
    // field indicating how many non-zero bytes are being used in the field. If we use fewer
    // than the max number of bytes for a given field, we still need to offset by the field
    // width so that the data may be unpacked into a struct on the Lattice side.
    //
    // Fields:
    // 4-byte pathDepth header
    // 5x 4-byte path indices = 20
    // 1 byte bool (EIP155)
    // 4 byte nonce (+4byte prefix)
    // 8 byte gasPrice (+4byte prefix)
    // 4 byte gasLimit (+4byte prefix)
    // 20 byte to address (+4byte prefix)
    // 32 byte value (+4byte prefix)
    // 1024 data bytes (+4byte prefix)
    // 1 byte chainID (a.k.a. `v`) (+4byte prefix)
    const txReqPayload = Buffer.alloc(1146);
    let off = 0;

    // 1. EIP155 switch and chainID
    //------------------
    txReqPayload.writeUInt8(Number(useEIP155), off); off++;
    txReqPayload.writeUInt8(Number(chainId), off); off++;

    // 2. BIP44 Path
    //------------------
    // First write the number of indices in this path (will probably always be 5, but
    // we want to keep this extensible)
    txReqPayload.writeUInt32LE(signerPath.length, off); off += 4;
    for (let i = 0; i < signerPath.length; i++) {
      txReqPayload.writeUInt32LE(signerPath[i], off); off += 4;
    }

    // 3. ETH TX request data
    //------------------
    txReqPayload.writeUInt32BE(data.nonce, off); off += 4;
    writeUInt64BE(data.gasPrice, txReqPayload, off); off += 8;
    txReqPayload.writeUInt32BE(data.gasLimit, off); off += 4;
    toBytes.copy(txReqPayload, off); off += 20;
    // Place the value (a BE number) in an offset such that it
    // can be interpreted as a number
    const valueOff = off + 32 - valueBytes.length;
    valueBytes.copy(txReqPayload, valueOff); off += 32;
    // Ensure data field isn't too long
    if (dataBytes && dataBytes.length > constants.ETH_DATA_MAX_SIZE) {
      return { err: `Data field too large (must be <=${constants.ETH_DATA_MAX_SIZE} bytes)` }
    }
    // Data
    txReqPayload.writeUInt16BE(dataBytes.length, off); off += 2;
    dataBytes.copy(txReqPayload, off); off += 1024;

    return { 
      rawTx,
      payload: txReqPayload,
      schema: constants.signingSchema.ETH_TRANSFER,  // We will use eth transfer for all ETH txs for v1 
      chainId,
      useEIP155,
      signerPath,
    };
  } catch (err) {
    return { err: err.message };
  }
}

// From ethereumjs-util
function stripZeros(a) {
  let first = a[0]
  while (a.length > 0 && first.toString() === '0') {
    a = a.slice(1)
    first = a[0]
  }
  return a
}

// Given a 64-byte signature [r,s] we need to figure out the v value
// and attah the full signature to the end of the transaction payload
exports.buildEthRawTx = function(tx, sig, address, useEIP155=true) {
  // RLP-encode the data we sent to the lattice
  const rlpEncoded = rlp.encode(tx.rawTx);
  const newSig = addRecoveryParam(rlpEncoded, sig, address, tx.chainId, useEIP155);
  // Use the signature to generate a new raw transaction payload
  const newRawTx = tx.rawTx.slice(0, 6);
  newRawTx.push(Buffer.from((newSig.v).toString(16), 'hex'));
  // Per `ethereumjs-tx`, RLP encoding should include signature components w/ stripped zeros
  // See: https://github.com/ethereumjs/ethereumjs-tx/blob/master/src/transaction.ts#L187
  newRawTx.push(stripZeros(newSig.r));
  newRawTx.push(stripZeros(newSig.s));
  return rlp.encode(newRawTx).toString('hex');
}

// Attach a recovery parameter to a signature by brute-forcing ECRecover
function addRecoveryParam(payload, sig, address, chainId, useEIP155) {
  try {
    // Rebuild the keccak256 hash here so we can `ecrecover`
    const hash = new Uint8Array(Buffer.from(keccak256(payload), 'hex'));
    sig.v = 27;
    // Fix signature componenet lengths to 32 bytes each
    const r = fixLen(sig.r, 32); sig.r = r;
    const s = fixLen(sig.s, 32); sig.s = s;
    // Calculate the recovery param
    const rs = new Uint8Array(Buffer.concat([r, s]));
    let pubkey = secp256k1.ecdsaRecover(rs, sig.v - 27, hash, false).slice(1)
    // If the first `v` value is a match, return the sig!
    if (pubToAddrStr(pubkey) === address.toString('hex')) {
      if (useEIP155 === true) sig.v  = updateRecoveryParam(sig.v, chainId);
      return sig;
    }
    // Otherwise, try the other `v` value
    sig.v = 28;
    pubkey = secp256k1.ecdsaRecover(rs, sig.v - 27, hash, false).slice(1)
    if (pubToAddrStr(pubkey) === address.toString('hex')) {
      if (useEIP155 === true) sig.v  = updateRecoveryParam(sig.v, chainId);
      return sig;
    } else {
      // If neither is a match, we should return an error
      throw new Error('Invalid Ethereum signature returned.');
    }
  } catch (err) {
    throw new Error(err);
  }
}
exports.addRecoveryParam = addRecoveryParam;

// Convert an RLP-serialized transaction (plus signature) into a transaction hash
exports.hashTransaction = function(serializedTx) {
  return keccak256(Buffer.from(serializedTx, 'hex')); 
}

// Ensure a param is represented by a buffer
function ensureHexBuffer(x) {
  if (x === null || x === 0) return Buffer.alloc(0);
  else if (Buffer.isBuffer(x)) x = x.toString('hex');
  if (typeof x === 'number') x = `${x.toString(16)}`;
  else if (typeof x === 'string' && x.slice(0, 2) === '0x') x = x.slice(2);
  if (x.length % 2 > 0) x = `0${x}`;
  return Buffer.from(x, 'hex');
}

// Returns address string given public key buffer
function pubToAddrStr(pub) {
  return keccak256(pub).slice(-40);
}

function fixLen(msg, length) {
  const buf = Buffer.alloc(length)
  if (msg.length < length) {
    msg.copy(buf, length - msg.length)
    return buf
  }
  return msg.slice(-length)
}

function updateRecoveryParam(v, chainId) {
  return v + (chainId * 2) + 8;
}

function writeUInt64BE(n, buf, off) {
  if (typeof n === 'number') n = n.toString(16);
  const preBuf = Buffer.alloc(8);
  const nStr = n.length % 2 === 0 ? n.toString(16) : `0${n.toString(16)}`;
  const nBuf = Buffer.from(nStr, 'hex');
  nBuf.copy(preBuf, preBuf.length - nBuf.length);
  preBuf.copy(buf, off);
  return preBuf;
}

function isASCII(str) {
    return (/^[\x00-\x7F]*$/).test(str)
}

const chainIds = {
  mainnet: 1,
  roptsten: 3,
  rinkeby: 4,
  kovan: 42,
  goerli: 5
}

const eip155 = {
  1: true,
  3: false,
  4:false,
  42: true,
  5: true
}

function buildPersonalSignRequest(req, input) {
  const L = ((input.signerPath.length + 1) * 4) + constants.ETH_MSG_MAX_SIZE + 4;
  let off = 0;
  req.payload = Buffer.alloc(L);
  req.payload.writeUInt8(constants.ethMsgProtocol.SIGN_PERSONAL.enumIdx, 0); off += 1;
  req.payload.writeUInt32LE(input.signerPath.length, off); off += 4;
  for (let i = 0; i < input.signerPath.length; i++) {
    req.payload.writeUInt32LE(input.signerPath[i], off); off += 4;
  }

  // Write the payload buffer. The payload can come in either as a buffer or as a string
  let payload = input.payload;
  // Determine if this is a hex string
  let displayHex = false;
  if (typeof input.payload === 'string') {
    if (input.payload.slice(0, 2) === '0x') {
      payload = ensureHexBuffer(input.payload)
      displayHex = false === isASCII(payload.toString());
    } else {
      payload = Buffer.from(input.payload)
    }
  } else if (typeof input.displayHex === 'boolean') {
    // If this is a buffer and the user has specified whether or not this
    // is a hex buffer with the optional argument, write that
    displayHex = input.displayHex
  }
  // Make sure we didn't run past the max size
  if (payload.length > constants.ETH_MSG_MAX_SIZE)
    throw new Error(`Your payload is ${payload.length} bytes, but can only be a maximum of ${constants.ETH_MSG_MAX_SIZE}`);
  // Write the payload and metadata into our buffer
  req.msg = payload;
  req.payload.writeUInt8(displayHex, off); off += 1;
  req.payload.writeUInt16LE(payload.length, off); off += 2;
  payload.copy(req.payload, off);
  return req;
}

function buildSignTypedDataRequest(req, input) {
  try {
    const T_CONST = constants.ethMsgProtocol.ETH_TYPED_DATA;
    const data = input.payload;
    if (!data.primaryType || !data.types[data.primaryType])
      throw new Error('primaryType must be specified and the type must be included.')
    if (!data.message || !data.domain)
      throw new Error('message and domain must be specified.')

    // Remove domain type if it was provided. This is not needed as we have a defined
    // C struct to parse the domain data (so the data better fit!)
    delete data.types.EIP712Domain;
    // Build our buffer. We will fill a buffer of max size.
    let off = 0;
    // First write general ETH message stuff
    req.payload = Buffer.alloc(constants.FIRMWARE_STRUCTS.encrypted.req.msgSz.sign);
    req.payload.writeUInt8(T_CONST.enumIdx, 0); off += 1;
    req.payload.writeUInt32LE(input.signerPath.length, off); off += 4;
    for (let i = 0; i < input.signerPath.length; i++) {
      req.payload.writeUInt32LE(input.signerPath[i], off); off += 4;
    }

    // 1. Serialize the domain first
    req.payload.writeUInt8(parseInt(data.domain.version), off); off++;
    req.payload.writeUInt32LE(parseInt(data.domain.chainId), off); off += 4;
    req.payload.writeUInt8(data.domain.name.length, off); off++;
    const domainNameBuf = Buffer.from(data.domain.name);
    if (domainNameBuf.length > T_CONST.domainNameMaxLen)
      throw new Error(`Domain name cannot be larger than ${T_CONST.domainNameMaxLen} characters.`);
    const fullDomainNameBuf = Buffer.alloc(T_CONST.domainNameMaxLen);
    domainNameBuf.copy(fullDomainNameBuf);
    fullDomainNameBuf.copy(req.payload, off); off += fullDomainNameBuf.length;
    const verifyingContract = ensureHexBuffer(data.domain.verifyingContract);
    if (verifyingContract.length !== 20)
      throw new Error(`Domain verifying contract must be a 20 byte address (got ${verifyingContract.length})`);
    verifyingContract.copy(req.payload, off); off += verifyingContract.length;
    // If there is a salt, record it. Create one otherwise.
    const saltBuf = Buffer.alloc(32);
    if (Buffer.isBuffer(data.domain.salt) && data.domain.salt.length === 32) {
      saltBuf.copy(req.payload, off); off += 32;
    } else {
      const saltPreImg = Buffer.concat([Buffer.from(new Date().toString()), verifyingContract]);
      const salt = Buffer.from(keccak256(saltPreImg), 'hex');
      req.signTypedDataSalt = salt;
      salt.copy(req.payload, off); off += 32;
    }

    // Now we will write a freeform buffer to allow for flexibility in type definitions.
    // The data is serialized like this:
    // | offsets | types | values

    // 2. Reserve space for type/values offsets. Each value is a u16. We will write the offsets later
    const typesArr = Object.keys(data.types);
    const numCustomTypes = typesArr.length;
    // Allocate space for the type and value offsets. Each custom type will gets its own u16 offset
    // and the last offset corresponds to the location of the value data.
    const offsets = Buffer.alloc(2 * (numCustomTypes + 1));
    // Write the number of custom types and move on to defining the types
    req.payload.writeUInt8(numCustomTypes, off); off++;
    // Add space for the offsets
    const rawDataStart = off;
    off += offsets.length;

    // 3. Serialize the types
    let dataOff = offsets.length; // Track where we are in the data buffer so we can write offsets
    if (typesArr > T_CONST.customTypesMaxNum)
      throw new Error(`Only a maximum of ${T_CONST.customTypesMaxNum} custom types are currently allowed.`)
    // Start with the primary type and splice it
    offsets.writeUInt16LE(dataOff, 0);
    let serializedType = _serializeCustomType(req.payload, data, data.primaryType);
    serializedType.copy(req.payload, off); off += serializedType.length; 
    dataOff += serializedType.length;
    // Splice out the primary type since it cannot be referenced by lower types
    typesArr.splice(typesArr.indexOf(data.primaryType), 1);
    // Now do the rest. Do not splice these, as they can theoretically reference each other.
    for (let i = 0; i < typesArr.length; i++) {
      offsets.writeUInt16LE(dataOff, 2*(i+1));
      serializedType = _serializeCustomType(req.payload, data, typesArr[i]);
      serializedType.copy(req.payload, off); off += serializedType.length; 
      dataOff += serializedType.length;
    }

    // 4. Add the type offsets in
    // Write the values offset
    offsets.writeUInt16LE(dataOff, offsets.length - 2);
    offsets.copy(req.payload, rawDataStart);

    // 5. Serialize the values
    // First capture the starting index of the values in our data buffer
    // Now serialize and write the values themselves
    const serializedValues = _serializeValues(data, data.message);
    serializedValues.copy(req.payload, off); off += serializedValues.length;
    // Sanity check, slice off extra, and return
    if (off - rawDataStart > T_CONST.rawDataMaxLen)
      throw new Error(`Type definitions + data is too large. Got ${off-rawDataStart} bytes; need <${T_CONST.rawDataMaxLen} bytes`);
    // Slice out the part of the buffer that we didn't use.
    req.payload = req.payload.slice(0, off);
    return req;
  } catch (err) {
    return { err: `Failed to build signTypedData request: ${err.message}` };
  }
}

function _serializeCustomType(req, data, key) {
  let off = 0;
  // Allocate a big buffer. We will slice off the unused portion before returning.
  const _constants = constants.ethMsgProtocol.ETH_TYPED_DATA;
  // type enum val (1 byte) + nameLen (1 byte) + name
  const _subTypeSz = (2 + _constants.nameMaxLen); 
  // num subtypes (1 bytes) + nameLen (1 byte) + name + subtypes
  const _customTypeSz = (2 + _constants.nameMaxLen +  (_constants.subTypesMaxNum * _subTypeSz)); 
  const buf = Buffer.alloc(_customTypeSz);
  const type = data.types[key];
  // Build a type name array. The primary type must be the first index (although we won't
  // use it). This is used to look up custom type names for subTypes
  const primaryTypeName = data.primaryType;
  let typesArr = Object.keys(data.types);
  typesArr.splice(typesArr.indexOf(primaryTypeName), 1);
  typesArr = [primaryTypeName].concat(typesArr);

  // We can now start serializing data!
  // name of this type
  if (key.length > constants.ethMsgProtocol.ETH_TYPED_DATA.nameMaxLen)
    throw new Error(`Parameter names must be 12 characters or fewer (${key}=${key.length})`);
  buf.writeUInt8(key.length, off); off ++;
  Buffer.from(key).copy(buf, off); off += Buffer.from(key).length;
  // numSubTypes
  buf.writeUInt8(type.length, off); off++;
  // Now write the sub types. These will usually be atomic/dynamic types but
  // can also be user-defined (a.k.a. "custom")
  type.forEach((subType) => {
    // First write the type code (and whether this is a custom type)
    if (typesArr.indexOf(subType.type) > -1) {
      // If this is a custom type, mark it as such and include the index of the type.
      buf.writeUInt8(1, off); off++; // Is a custom type
      // For custom type, we do not need to write the name. 
      // It will be referenced by the following index:
      buf.writeUInt32LE(typesArr.indexOf(subType.type), off); off += 4;
    } else {
      // If this is not a custom type, look for the atomic/dynamic type code.
      buf.writeUInt8(0, off); off++; // Not a custom type
      const code = constants.ethMsgProtocol.ETH_TYPED_DATA.typeCodes[subType.type];
      // If we can't find the type defined, throw an error here.
      if (typeof code !== 'number')
        throw new Error(`Could not find type: ${subType.type}`);
      buf.writeUInt32LE(code, off); off += 4;
    }
    // Now the name (including length)
    const name = Buffer.from(subType.name);
    buf.writeUInt8(name.length, off); off ++;
    name.copy(buf, off); off += name.length;
  })
  return buf.slice(0, off);
}

function _serializeValues(data, msg, currentType=null) {
  let off = 0;
  // Allocate a big buffer. We will slice off the unused portion before returning.
  const buf = Buffer.alloc(constants.ethMsgProtocol.ETH_TYPED_DATA.rawDataMaxLen);
  const subMsg = currentType === null ? msg : msg[currentType.name];
  const type = currentType === null ? data.types[data.primaryType] : data.types[currentType.type];
  const customTypesArr = Object.keys(data.types);
  type.forEach((subType) => {
    // If this is a custom type we recursively serialize that nested object first
    if (customTypesArr.indexOf(subType.type) > -1) {
      const subBuf = _serializeValues(data, subMsg[subType.name], subType);
      subBuf.copy(buf, off); off += subBuf.length;
    } else {
      // Otherwise we encode this object based on the order of subTypes
      const encVal = _encodeTypeValue(subType.type, msg[subType.name]);
      encVal.copy(buf, off); off += encVal.length;
    }
  })
  if (off > constants.ethMsgProtocol.ETH_TYPED_DATA.rawDataMaxLen)
    throw new Error(`Too much data. Can only currently fit ${constants.ethMsgProtocol.ETH_TYPED_DATA.rawDataMaxLen} bytes, but got ${off}.`)
  return buf.slice(0, off);
}

function _encodeTypeValue(type, msg) {
  let buf;
  // Handle fixed size bytes (can be 1-32 bytes)
  if (type.slice(0, 5) === 'bytes') {
    msg = ensureHexBuffer(msg);
    const n = parseInt(type.slice(5));
    if (n < 1 || n > 32)
      throw new Error('Only bytes1-bytes32 are supported.');
    if (msg.length !== n)
      throw new Error(`${type} provided, but got message of size ${msg.length}`);
    buf = Buffer.alloc(n);
    msg.copy(buf);
    return buf;
  }
  switch (type) {
    case 'uint8':
    case 'int8':
      buf = Buffer.alloc(1);
      Buffer.from([msg]).copy(buf);
      return buf;
    case 'uint16':
    case 'int16':
      buf = Buffer.alloc(2);
      Buffer.from([msg]).copy(buf);
      return buf;
    case 'uint32':
    case 'int32':
      buf = Buffer.alloc(4);
      Buffer.from([msg]).copy(buf);
      return buf;
    case 'uint64':
    case 'int64':
      buf = Buffer.alloc(8);
      Buffer.from([msg]).copy(buf);
      return buf;
    case 'bool':
      buf = Buffer.alloc(1);
      Buffer.from([msg === true ? 1 : 0]).copy(buf);
      return buf;
    case 'uint256':
    case 'int256':
      buf = Buffer.alloc(32);
      Buffer.from((msg).toString(16), 'hex').copy(buf);
      return buf;
    case 'address':
      buf = Buffer.alloc(20);
      ensureHexBuffer(msg).copy(buf);
      return buf;
    case 'bytes':
      buf = Buffer.alloc(2 + msg.length);
      buf.writeUInt16LE(msg.length);
      msg.copy(buf, 2);
      return buf;
    case 'string':
      buf = Buffer.alloc(2 + msg.length);
      buf.writeUInt16LE(Buffer.from(msg).length)
      Buffer.from(msg).copy(buf, 2)
      return buf;
    default:
      throw new Error(`Cannot encode unknown type: ${type}`);
  }
}

exports.chainIds = chainIds;