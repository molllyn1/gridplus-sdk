const flog = require('./firmwareLog.json');

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
    const vals = flog[version]; 
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
    console.log('loaded structs', FIRMWARE_STRUCTS)
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
        enumIdx: 0,           // Enum index of this protocol in Lattice firmware
    },
    ETH_TYPED_DATA: {
        enumIdx: 1,           // Enum index of this protocol in Lattice firmware
        nameMaxLen: 20,       // Max number of characters for param name
        rawDataMaxLen: 1024,  // Max size of raw data payload in bytes
        subTypesMaxNum: 6,    // Number of subTypes that may be included in a custom type
        customTypesMaxNum: 3, // Max number of custom types in message (*including* primaryType)
        typeCodes: {          // Enum indices of data types in Lattice firmware
            'bytes1': 0,
            'bytes32': 1,
            'uint8': 2,
            'uint256': 3,
            'int8': 4,
            'int256': 5,
            'bool': 6,
            'address': 7,
            'bytes': 9,
            'string': 10,
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