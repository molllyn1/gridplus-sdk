const fwConst = require('./fwConsts.json');

// Information about C structs in Lattice firmware.
// !! NOTE: The comments are based on v1 values! See `firmwareLog.json` for the values that correspond
// to each protocol version. !!
const FIRMWARE_STRUCTS = {
    encrypted: {
        req: {
            msgSz: {    // Lengths of encrypted request structs
                        // NOTE: Only `sign` is provided here because it may be larger than the largest res sizes
                        //       and thus may affect ENC_MSG_LEN. All other requests are small so they do not need 
                        //       to be listed here.
                sign: 0,
            },
            extraDataSz: 0, // Extra data INSIDE decrypted request: requestType (1 byte) + checksum (4 bytes)

        },
        res: {  // Members of GpDecryptedResponse_t; does NOT include `ephemKey` and `checksum` (see `extraDataInside`) 
            msgSz: {                                // Lengths of encrypted response structs
                finalizePair: 0,                    // Only contains the pubkey
                getAddresses: 0,                    // 10x 129 byte strings (128 bytes + null terminator)
                sign: 0,                            // 1 DER signature for ETH, 10 for BTC + change pubkeyhash
                getWallets: 0,                      // 71 bytes per wallet record (response contains internal and external)
                test: 0                             // Max size of test response payload
            },
            extraDataSz: 0, // Extra data INSIDE decrypted response: pubkey (65 bytes) + checksum (4 bytes)
        },
        metaData: 0,    // Header data OUTSIDE decrypted message;
                        // Prefix:
                        // * protocol version (1 byte)
                        // * response type, reserved (1 byte) -- not used
                        // * response id (4 bytes) -- not used
                        // * payload length (2 bytes)
                        // * response code (1 byte)
                        // Suffix:
                        // * checksum (4 bytes) -- NOT the same checksum as inside the decrypted msg
        totalSz: 0,     // Calculated when this file is loaded
    }
}

function loadFirmwareConstants(version) {
    const vals = fwConst[version]; 
    FIRMWARE_STRUCTS.encrypted.req.msgSz.sign = vals.encMsgSz.req.sign;
    FIRMWARE_STRUCTS.encrypted.req.extraDataSz = vals.encMsgSz.req.extraDataSz;
    FIRMWARE_STRUCTS.encrypted.res.msgSz.finalizePair = vals.encMsgSz.res.finalizePair;
    FIRMWARE_STRUCTS.encrypted.res.msgSz.getAddresses = vals.encMsgSz.res.getAddresses;
    FIRMWARE_STRUCTS.encrypted.res.msgSz.sign = vals.encMsgSz.res.sign;
    FIRMWARE_STRUCTS.encrypted.res.msgSz.getWallets = vals.encMsgSz.res.getWallets;
    FIRMWARE_STRUCTS.encrypted.res.msgSz.test = vals.encMsgSz.res.test;
    FIRMWARE_STRUCTS.encrypted.res.extraDataSz = vals.encMsgSz.res.extraDataSz;
    FIRMWARE_STRUCTS.encrypted.metaData = vals.encMsgSz.metaDataSz;

    let maxMsgSz = 0;
    const metaDataSz = FIRMWARE_STRUCTS.encrypted.metaData;
    const reqExtraDataSz = FIRMWARE_STRUCTS.encrypted.req.extraDataSz;
    const resExtraDataSz = FIRMWARE_STRUCTS.encrypted.res.extraDataSz;
    Object.keys(FIRMWARE_STRUCTS.encrypted.req.msgSz).forEach((k) => {
        const sz = FIRMWARE_STRUCTS.encrypted.req.msgSz[k];
        if (sz + reqExtraDataSz > maxMsgSz)
            maxMsgSz = sz + reqExtraDataSz;
    })
    Object.keys(FIRMWARE_STRUCTS.encrypted.res.msgSz).forEach((k) => {
        const sz = FIRMWARE_STRUCTS.encrypted.res.msgSz[k];
        if (sz + resExtraDataSz > maxMsgSz)
            maxMsgSz = sz + resExtraDataSz;
    })
    FIRMWARE_STRUCTS.encrypted.totalSz = maxMsgSz + metaDataSz;
}

const deviceCodes = {
    'CONNECT': 1,
    'ENCRYPTED_REQUEST': 2,
}

const encReqCodes = {
    'FINALIZE_PAIRING': 0x00,
    'GET_ADDRESSES': 0x01,
    'ADD_PERMISSION': 0x02,
    'SIGN_TRANSACTION': 0x03,
    'GET_WALLETS': 0x04,
    'TEST': 0x05,
}

const messageConstants = {
    'NOT_PAIRED': 0x00,
    'PAIRED': 0x01,
}

const addressSizes = {
    'BTC': 20,  // 20 byte pubkeyhash
    'ETH': 20,  // 20 byte address not including 0x prefix
}
  
const responseCodes = {
    RESP_SUCCESS: 0x00,
    RESP_ERR_INVALID_MSG: 0x80,
    RESP_ERR_UNSUPPORTED_VER: 0x81,
    RESP_ERR_DEV_BUSY: 0x82,
    RESP_ERR_USER_TIMEOUT: 0x83,
    RESP_ERR_USER_DECLINED: 0x84,
    RESP_ERR_PAIR_FAIL: 0x85,
    RESP_ERR_PAIR_DISABLED: 0x86,
    RESP_ERR_PERMISSION_DISABLED: 0x87,
    RESP_ERR_INTERNAL: 0x88,
    RESP_ERR_GCE_TIMEOUT: 0x89,
    RESP_ERR_WALLET_NOT_PRESENT: 0x8a,
    RESP_ERR_DEV_LOCKED: 0x8b,
    RESP_ERR_DISABLED: 0x8c
}

const responseMsgs = {
    [responseCodes.RESP_SUCCESS]: 0x00,
    [responseCodes.RESP_ERR_INVALID_MSG]: 'Invalid Request',
    [responseCodes.RESP_ERR_UNSUPPORTED_VER]: 'Unsupported Version',
    [responseCodes.RESP_ERR_DEV_BUSY]: 'Device Busy',
    [responseCodes.RESP_ERR_USER_TIMEOUT]: 'Timeout Waiting for User',
    [responseCodes.RESP_ERR_USER_DECLINED]: 'Request Declined by User',
    [responseCodes.RESP_ERR_PAIR_FAIL]: 'Pairing Failed',
    [responseCodes.RESP_ERR_PAIR_DISABLED]: 'Pairing is Currently Disabled',
    [responseCodes.RESP_ERR_PERMISSION_DISABLED]: 'Automated Signing is Currently Disabled',
    [responseCodes.RESP_ERR_INTERNAL]: 'Device Error',
    [responseCodes.RESP_ERR_GCE_TIMEOUT]: 'Timeout',
    [responseCodes.RESP_ERR_WALLET_NOT_PRESENT]: 'Incorrect Wallet UID Provided',
    [responseCodes.RESP_ERR_DEV_LOCKED]: 'Device Locked',
    [responseCodes.RESP_ERR_DISABLED]: 'Disabled',
}
 

const signingSchema = {
    BTC_TRANSFER: 0,
    ETH_TRANSFER: 1,
    ERC20_TRANSFER: 2,
    ETH_MSG: 3,
}

const ethMsgProtocol = {
    SIGN_PERSONAL: {
        str: 'signPersonal',
        enumIdx: 0,             // Enum index of this protocol in Lattice firmware
    },
    EIP712: {
        str: 'eip712',
        enumIdx: 1,
        rawDataMaxLen: 1629,    // Max size of raw data payload in bytes
        typeCodes: {            // Enum indices of data types in Lattice firmware
            'bytes1': 1,
            'bytes2': 2,
            'bytes3': 3,
            'bytes4': 4,
            'bytes5': 5,
            'bytes6': 6,
            'bytes7': 7,
            'bytes8': 8,
            'bytes9': 9,
            'bytes10': 10,
            'bytes11': 11,
            'bytes12': 12,
            'bytes13': 13,
            'bytes14': 14,
            'bytes15': 15,
            'bytes16': 16,
            'bytes17': 17,
            'bytes18': 18,
            'bytes19': 19,
            'bytes20': 20,
            'bytes21': 21,
            'bytes22': 22,
            'bytes23': 23,
            'bytes24': 24,
            'bytes25': 25,
            'bytes26': 27,
            'bytes27': 28,
            'bytes28': 29,
            'bytes29': 30,
            'bytes30': 31,
            'bytes31': 32,
            'bytes32': 33,
            'uint8': 34,
            'uint16': 35,
            'uint32': 36,
            'uint64': 37,
            'uint256': 38,
            'int8': 39,
            'int16': 40,
            'int32': 41,
            'int64': 42,
            'int256': 43,
            'bool': 44,
            'address': 45,
            'bytes': 47,
            'string': 48,
        }
    },
}

// Consistent with Lattice's IV
const AES_IV = [0x6d, 0x79, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64]
const ADDR_STR_LEN = 129; // 128-char strings (null terminated)
const ETH_DATA_MAX_SIZE = 1024; // Maximum number of bytes that can go in the data field
const ETH_MSG_MAX_SIZE = 1024; // Maximum number of bytes that can be used in a message signing request
const REQUEST_TYPE_BYTE = 0x02; // For all HSM-bound requests
const HARDENED_OFFSET = 0x80000000; // Hardened offset

const BASE_URL = 'https://signing.gridpl.us';

module.exports = {
    ADDR_STR_LEN,
    AES_IV,
    BASE_URL,
    addressSizes,
    deviceCodes,
    encReqCodes,
    ethMsgProtocol,
    messageConstants,
    responseCodes,
    responseMsgs,
    signingSchema,
    loadFirmwareConstants,
    ETH_DATA_MAX_SIZE,
    ETH_MSG_MAX_SIZE,
    REQUEST_TYPE_BYTE,
    HARDENED_OFFSET,
    FIRMWARE_STRUCTS,
}