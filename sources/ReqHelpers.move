module free_tunnel_sui::req_helpers {

    // =========================== Packages ===========================
    use sui::hex;
    use sui::event;
    use sui::table;
    use sui::clock::{Self, Clock};
    use std::type_name::{Self, TypeName};
    use free_tunnel_sui::utils::smallU64ToString;


    // =========================== Constants ==========================
    const CHAIN: u8 = 0xa4;

    const ETOKEN_INDEX_OCCUPIED: u64 = 0;
    const ETOKEN_INDEX_CANNOT_BE_ZERO: u64 = 1;
    const ETOKEN_INDEX_NONEXISTENT: u64 = 2;
    const EINVALID_REQ_ID_LENGTH: u64 = 3;
    const ENOT_FROM_CURRENT_CHAIN: u64 = 4;
    const ENOT_TO_CURRENT_CHAIN: u64 = 5;
    const ECREATED_TIME_TOO_EARLY: u64 = 6;
    const ECREATED_TIME_TOO_LATE: u64 = 7;
    const EAMOUNT_CANNOT_BE_ZERO: u64 = 8;
    const ETOKEN_TYPE_MISMATCH: u64 = 9;
    const EINVALID_ACTION: u64 = 10;

    public(package) fun BRIDGE_CHANNEL(): vector<u8> { b"Merlin mBTC Bridge" }
    public(package) fun PROPOSE_PERIOD(): u64 { 172800 }         // 48 hours
    public(package) fun EXPIRE_PERIOD(): u64 { 259200 }          // 72 hours
    public(package) fun EXPIRE_EXTRA_PERIOD(): u64 { 345600 }    // 96 hours
    public(package) fun ETH_SIGN_HEADER(): vector<u8> { b"\x19Ethereum Signed Message:\n" }

    // ============================ Storage ===========================
    public struct ReqHelpersStorage has key, store {
        id: UID,
        tokens: table::Table<u8, TypeName>,
        tokenDecimals: table::Table<u8, u8>,
    }

    public(package) fun initReqHelpersStorage(ctx: &mut TxContext): ReqHelpersStorage {
        ReqHelpersStorage {
            id: object::new(ctx),
            tokens: table::new(ctx),
            tokenDecimals: table::new(ctx),
        }
    }

    public struct TokenAdded has copy, drop {
        tokenIndex: u8,
        tokenType: TypeName,
    }

    public struct TokenRemoved has copy, drop {
        tokenIndex: u8,
        tokenType: TypeName,
    }


    // =========================== Functions ===========================
    public(package) fun addTokenInternal<CoinType>(tokenIndex: u8, decimals: u8, store: &mut ReqHelpersStorage) {
        assert!(!store.tokens.contains(tokenIndex), ETOKEN_INDEX_OCCUPIED);
        assert!(tokenIndex > 0, ETOKEN_INDEX_CANNOT_BE_ZERO);
        let tokenType = type_name::get<CoinType>();
        store.tokens.add(tokenIndex, tokenType);
        store.tokenDecimals.add(tokenIndex, decimals);
        event::emit(TokenAdded { tokenIndex, tokenType });
    }

    public(package) fun removeTokenInternal(tokenIndex: u8, store: &mut ReqHelpersStorage) {
        assert!(store.tokens.contains(tokenIndex), ETOKEN_INDEX_NONEXISTENT);
        assert!(tokenIndex > 0, ETOKEN_INDEX_CANNOT_BE_ZERO);
        let tokenType = store.tokens.remove(tokenIndex);
        store.tokenDecimals.remove(tokenIndex);
        event::emit(TokenRemoved { tokenIndex, tokenType });
    }

    /// `reqId` in format of `version:uint8|createdTime:uint40|action:uint8|tokenIndex:uint8|amount:uint64|from:uint8|to:uint8|(TBD):uint112`
    public(package) fun versionFrom(reqId: vector<u8>): u8 {
        reqId[0]
    }

    public(package) fun createdTimeFrom(reqId: vector<u8>): u64 {
        let mut time = reqId[1] as u64;
        let mut i = 2;
        while (i < 6) {
            time = (time << 8) + (reqId[i] as u64);
            i = i + 1;
        };
        time
    }

    public(package) fun checkCreatedTimeFrom(reqId: vector<u8>, clockObject: &Clock): u64 {
        let time = createdTimeFrom(reqId);
        assert!(time > clock::timestamp_ms(clockObject) / 1000 - PROPOSE_PERIOD(), ECREATED_TIME_TOO_EARLY);
        assert!(time < clock::timestamp_ms(clockObject) / 1000 + 60, ECREATED_TIME_TOO_LATE);
        time
    }

    public(package) fun actionFrom(reqId: vector<u8>): u8 {
        reqId[6]
    }

    fun decodeTokenIndex(reqId: vector<u8>): u8 {
        reqId[7]
    }

    public(package) fun checkTokenType<CoinType>(tokenIndex: u8, store: &ReqHelpersStorage) {
        let tokenTypeExpected = store.tokens[tokenIndex];
        let tokenTypeActual = type_name::get<CoinType>();
        assert!(tokenTypeExpected == tokenTypeActual, ETOKEN_TYPE_MISMATCH);
    }

    public(package) fun tokenIndexFrom<CoinType>(reqId: vector<u8>, store: &ReqHelpersStorage): u8 {
        let tokenIndex = decodeTokenIndex(reqId);
        assert!(store.tokens.contains(tokenIndex), ETOKEN_INDEX_NONEXISTENT);
        checkTokenType<CoinType>(tokenIndex, store);
        tokenIndex
    }

    fun decodeAmount(reqId: vector<u8>): u64 {
        let mut amount = reqId[8] as u64;
        let mut i = 9;
        while (i < 16) {
            amount = (amount << 8) + (reqId[i] as u64);
            i = i + 1;
        };
        assert!(amount > 0, EAMOUNT_CANNOT_BE_ZERO);
        amount
    }

    public(package) fun amountFrom(reqId: vector<u8>, store: &ReqHelpersStorage): u64 {
        let mut amount = decodeAmount(reqId);
        let tokenIndex = decodeTokenIndex(reqId);
        let decimals = store.tokenDecimals[tokenIndex];
        if (decimals > 6) {
            amount = amount * (10 as u64).pow(decimals - 6);
        } else if (decimals < 6) {
            amount = amount / (10 as u64).pow(6 - decimals);
        };
        amount
    }

    public(package) fun msgFromReqSigningMessage(reqId: vector<u8>): vector<u8> {
        assert!(reqId.length() == 32, EINVALID_REQ_ID_LENGTH);
        let specificAction = actionFrom(reqId) & 0x0f;

        match (specificAction) {
            1 => {
                (vector[
                    ETH_SIGN_HEADER(),
                    smallU64ToString(3 + BRIDGE_CHANNEL().length() + 29 + 66),
                    b"[", BRIDGE_CHANNEL(), b"]\n",
                    b"Sign to execute a lock-mint:\n",
                    b"0x", hex::encode(reqId),
                ]).flatten()
            },
            2 => {
                (vector[
                    ETH_SIGN_HEADER(),
                    smallU64ToString(3 + BRIDGE_CHANNEL().length() + 31 + 66),
                    b"[", BRIDGE_CHANNEL(), b"]\n",
                    b"Sign to execute a burn-unlock:\n",
                    b"0x", hex::encode(reqId),
                ]).flatten()
            },
            3 => {
                (vector[
                    ETH_SIGN_HEADER(),
                    smallU64ToString(3 + BRIDGE_CHANNEL().length() + 29 + 66),
                    b"[", BRIDGE_CHANNEL(), b"]\n",
                    b"Sign to execute a burn-mint:\n",
                    b"0x", hex::encode(reqId),
                ]).flatten()
            },
            _ => {
                assert!(false, EINVALID_ACTION);
                vector::empty<u8>()
            }
        }
    }

    public(package) fun assertFromChainOnly(reqId: vector<u8>) {
        assert!(CHAIN == reqId[16], ENOT_FROM_CURRENT_CHAIN);
    }

    public(package) fun assertToChainOnly(reqId: vector<u8>) {
        assert!(CHAIN == reqId[17], ENOT_TO_CURRENT_CHAIN);
    }


    #[test]
    fun testHexEncode() {
        let value = vector[0x33, 0x45];
        assert!(hex::encode(value) == b"3345");
    }

    #[test]
    fun testDecodingReqid() {
        // `version:uint8|createdTime:uint40|action:uint8|tokenIndex:uint8|amount:uint64|from:uint8|to:uint8|(TBD):uint112`
        let reqId = x"112233445566778899aabbccddeeff00a0a0ffffffffffffffffffffffffffff";
        assert!(versionFrom(reqId) == 0x11);
        assert!(createdTimeFrom(reqId) == 0x2233445566);
        assert!(actionFrom(reqId) == 0x77);
        assert!(decodeTokenIndex(reqId) == 0x88);
        assert!(decodeAmount(reqId) == 0x99aabbccddeeff00);
        assertFromChainOnly(reqId);
        assertToChainOnly(reqId);
    }

    #[test]
    fun testMsgFromReqSigningMessage1() {
        // action 1: lock-mint
        let reqId = x"112233445566018899aabbccddeeff004040ffffffffffffffffffffffffffff";
        let expected = b"\x19Ethereum Signed Message:\n112[Sui Bridge]\nSign to execute a lock-mint:\n0x112233445566018899aabbccddeeff004040ffffffffffffffffffffffffffff";
        assert!(msgFromReqSigningMessage(reqId) == expected);
    }

    #[test]
    fun testMsgFromReqSigningMessage2() {
        // action 2: burn-unlock
        let reqId = x"112233445566028899aabbccddeeff004040ffffffffffffffffffffffffffff";
        let expected = b"\x19Ethereum Signed Message:\n114[Sui Bridge]\nSign to execute a burn-unlock:\n0x112233445566028899aabbccddeeff004040ffffffffffffffffffffffffffff";
        assert!(msgFromReqSigningMessage(reqId) == expected);
    }

    #[test]
    fun testMsgFromReqSigningMessage3() {
        // action 3: burn-mint
        let reqId = x"112233445566038899aabbccddeeff004040ffffffffffffffffffffffffffff";
        let expected = b"\x19Ethereum Signed Message:\n112[Sui Bridge]\nSign to execute a burn-mint:\n0x112233445566038899aabbccddeeff004040ffffffffffffffffffffffffffff";
        assert!(msgFromReqSigningMessage(reqId) == expected);
    }

    #[test]
    #[expected_failure(abort_code = EINVALID_ACTION)]
    fun testMsgFromReqSigningMessage4() {
        let reqId = x"112233445566048899aabbccddeeff004040ffffffffffffffffffffffffffff";
        assert!(msgFromReqSigningMessage(reqId) == vector::empty<u8>());
    }

}