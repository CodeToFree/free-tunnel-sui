module free_tunnel_sui::atomic_mint {

    // =========================== Packages ===========================
    use sui::bag;
    use sui::event;
    use sui::table;
    use sui::coin::{Self, Coin};
    use sui::clock::{Self, Clock};
    use free_tunnel_sui::utils;
    use free_tunnel_sui::req_helpers::{Self, ReqHelpersStorage, EXPIRE_PERIOD, EXPIRE_EXTRA_PERIOD};
    use free_tunnel_sui::permissions::{Self, PermissionsStorage};
    use deployer::access_control::{AccessConfig, MinterCap, BurnerCap};
    use deployer::fbtc::{mint, burn, TreasuryCapManager};


    // =========================== Constants ==========================
    const EXECUTED_PLACEHOLDER: address = @0xed;

    const EINVALID_REQ_ID: u64 = 50;
    const EINVALID_RECIPIENT: u64 = 51;
    const ENOT_LOCK_MINT: u64 = 52;
    const ENOT_BURN_MINT: u64 = 53;
    const EWAIT_UNTIL_EXPIRED: u64 = 54;
    const EINVALID_PROPOSER: u64 = 55;
    const ENOT_BURN_UNLOCK: u64 = 56;
    const EALREADY_HAVE_MINTERCAP: u64 = 57;


    // ============================ Storage ===========================
    public struct AtomicMintStorage has key, store {
        id: UID,
        proposedMint: table::Table<vector<u8>, address>,
        proposedBurn: table::Table<vector<u8>, address>,
        burningCoins: bag::Bag,     // tokenIndex -> Pending Coin Object
        minterCaps: bag::Bag,      // tokenIndex -> MinterCap
        burnerCaps: bag::Bag,      // tokenIndex -> BurnerCap
    }

    public struct TokenMintProposed has copy, drop {
        reqId: vector<u8>,
        recipient: address,
    }

    public struct TokenMintExecuted has copy, drop {
        reqId: vector<u8>,
        recipient: address,
    }

    public struct TokenMintCancelled has copy, drop {
        reqId: vector<u8>,
        recipient: address,
    }

    public struct TokenBurnProposed has copy, drop {
        reqId: vector<u8>,
        proposer: address,
    }

    public struct TokenBurnExecuted has copy, drop {
        reqId: vector<u8>,
        proposer: address,
    }

    public struct TokenBurnCancelled has copy, drop {
        reqId: vector<u8>,
        proposer: address,
    }


    /**
     * @dev Cannot pass more parameters here, so you need to transfer admin, update proposers
     *          and update executors manually later.
     */
    fun init(ctx: &mut TxContext) {
        let permissionStorage = permissions::initPermissionsStorage(ctx);
        transfer::public_share_object(permissionStorage);

        let reqHelpersStorage = req_helpers::initReqHelpersStorage(ctx);
        transfer::public_share_object(reqHelpersStorage);

        let atomicMintStorage = AtomicMintStorage {
            id: object::new(ctx),
            proposedMint: table::new(ctx),
            proposedBurn: table::new(ctx),
            burningCoins: bag::new(ctx),
            minterCaps: bag::new(ctx),
            burnerCaps: bag::new(ctx),
        };
        transfer::public_share_object(atomicMintStorage);
    }


    // =========================== Functions ===========================
    public entry fun addToken<CoinType>(
        tokenIndex: u8,
        decimals: u8,
        storeP: &mut PermissionsStorage,
        storeR: &mut ReqHelpersStorage,
        ctx: &mut TxContext,
    ) {
        permissions::assertOnlyAdmin(storeP, ctx);
        req_helpers::addTokenInternal<CoinType>(tokenIndex, decimals, storeR);
    }

    public entry fun transferCaps<CoinType>(
        tokenIndex: u8,
        minterCap: MinterCap,
        burnerCap: BurnerCap,
        storeA: &mut AtomicMintStorage,
        storeR: &mut ReqHelpersStorage,
    ){
        req_helpers::checkTokenType<CoinType>(tokenIndex, storeR);
        assert!(!storeA.minterCaps.contains(tokenIndex), EALREADY_HAVE_MINTERCAP);
        storeA.minterCaps.add(tokenIndex, minterCap);
        storeA.burnerCaps.add(tokenIndex, burnerCap);
    }

    public entry fun removeToken(
        tokenIndex: u8,
        storeA: &mut AtomicMintStorage,
        storeP: &mut PermissionsStorage,
        storeR: &mut ReqHelpersStorage,
        ctx: &mut TxContext,
    ) {
        permissions::assertOnlyAdmin(storeP, ctx);
        req_helpers::removeTokenInternal(tokenIndex, storeR);
        if (storeA.minterCaps.contains(tokenIndex)) {
            let minterCap: MinterCap = storeA.minterCaps.remove(tokenIndex);
            let burnerCap: BurnerCap = storeA.burnerCaps.remove(tokenIndex);
            transfer::public_transfer(minterCap, ctx.sender());
            transfer::public_transfer(burnerCap, ctx.sender());
        }
    }

    public entry fun proposeMint<CoinType>(
        reqId: vector<u8>,
        recipient: address,
        storeA: &mut AtomicMintStorage,
        storeP: &mut PermissionsStorage,
        storeR: &mut ReqHelpersStorage,
        clockObject: &Clock,
        ctx: &mut TxContext,
    ) {
        permissions::assertOnlyProposer(storeP, ctx);
        req_helpers::assertToChainOnly(reqId);
        assert!(req_helpers::actionFrom(reqId) & 0x0f == 1, ENOT_LOCK_MINT);
        proposeMintPrivate<CoinType>(reqId, recipient, storeA, storeR, clockObject);
    }

    public entry fun proposeMintFromBurn<CoinType>(
        reqId: vector<u8>,
        recipient: address,
        storeA: &mut AtomicMintStorage,
        storeP: &mut PermissionsStorage,
        storeR: &mut ReqHelpersStorage,
        clockObject: &Clock,
        ctx: &mut TxContext,
    ) {
        permissions::assertOnlyProposer(storeP, ctx);
        req_helpers::assertToChainOnly(reqId);
        assert!(req_helpers::actionFrom(reqId) & 0x0f == 3, ENOT_BURN_MINT);
        proposeMintPrivate<CoinType>(reqId, recipient, storeA, storeR, clockObject);
    }

    fun proposeMintPrivate<CoinType>(
        reqId: vector<u8>,
        recipient: address,
        storeA: &mut AtomicMintStorage,
        storeR: &ReqHelpersStorage,
        clockObject: &Clock,
    ) {
        req_helpers::checkCreatedTimeFrom(reqId, clockObject);
        assert!(!storeA.proposedMint.contains(reqId), EINVALID_REQ_ID);
        assert!(recipient != EXECUTED_PLACEHOLDER, EINVALID_RECIPIENT);

        req_helpers::amountFrom(reqId, storeR);
        req_helpers::tokenIndexFrom<CoinType>(reqId, storeR);
        storeA.proposedMint.add(reqId, recipient);

        event::emit(TokenMintProposed{ reqId, recipient });
    }

    public entry fun executeMint<CoinType>(
        reqId: vector<u8>,
        r: vector<vector<u8>>,
        yParityAndS: vector<vector<u8>>,
        executors: vector<vector<u8>>,
        exeIndex: u64,
        fbtcConfig: &mut AccessConfig,
        treasuryCapManager: &mut TreasuryCapManager,
        storeA: &mut AtomicMintStorage,
        storeP: &mut PermissionsStorage,
        storeR: &ReqHelpersStorage,
        clockObject: &Clock,
        ctx: &mut TxContext,
    ) {
        let recipient = storeA.proposedMint[reqId];
        assert!(recipient != EXECUTED_PLACEHOLDER, EINVALID_REQ_ID);

        let message = req_helpers::msgFromReqSigningMessage(reqId);
        permissions::checkMultiSignatures(
            message, r, yParityAndS, executors, exeIndex, clockObject, storeP,
        );

        *storeA.proposedMint.borrow_mut(reqId) = EXECUTED_PLACEHOLDER;

        let amount = req_helpers::amountFrom(reqId, storeR);
        let tokenIndex = req_helpers::tokenIndexFrom<CoinType>(reqId, storeR);

        let coinMinted = mint(
            amount, treasuryCapManager, storeA.minterCaps.borrow(tokenIndex),
            fbtcConfig, ctx
        );
        transfer::public_transfer(coinMinted, recipient);
        event::emit(TokenMintExecuted{ reqId, recipient });
    }

    public entry fun cancelMint(
        reqId: vector<u8>,
        storeA: &mut AtomicMintStorage,
        clockObject: &Clock,
    ) {
        let recipient = storeA.proposedMint[reqId];
        assert!(recipient != EXECUTED_PLACEHOLDER, EINVALID_REQ_ID);
        assert!(
            clock::timestamp_ms(clockObject) / 1000 > req_helpers::createdTimeFrom(reqId)
            + EXPIRE_EXTRA_PERIOD(), EWAIT_UNTIL_EXPIRED
        );

        storeA.proposedMint.remove(reqId);
        event::emit(TokenMintCancelled{ reqId, recipient });
    }


    public entry fun proposeBurn<CoinType>(
        reqId: vector<u8>,
        coinList: vector<Coin<CoinType>>,
        storeA: &mut AtomicMintStorage,
        storeR: &ReqHelpersStorage,
        clockObject: &Clock,
        ctx: &mut TxContext,
    ) {
        req_helpers::assertToChainOnly(reqId);
        assert!(req_helpers::actionFrom(reqId) & 0x0f == 2, ENOT_BURN_UNLOCK);
        proposeBurnPrivate<CoinType>(
            reqId, coinList, storeA, storeR, clockObject, ctx,
        );
    }

    public entry fun proposeBurnForMint<CoinType>(
        reqId: vector<u8>,
        coinList: vector<Coin<CoinType>>,
        storeA: &mut AtomicMintStorage,
        storeR: &ReqHelpersStorage,
        clockObject: &Clock,
        ctx: &mut TxContext,
    ) {
        req_helpers::assertFromChainOnly(reqId);
        assert!(req_helpers::actionFrom(reqId) & 0x0f == 3, ENOT_BURN_MINT);
        proposeBurnPrivate<CoinType>(
            reqId, coinList, storeA, storeR, clockObject, ctx,
        );
    }

    fun proposeBurnPrivate<CoinType>(
        reqId: vector<u8>,
        coinList: vector<Coin<CoinType>>,
        storeA: &mut AtomicMintStorage,
        storeR: &ReqHelpersStorage,
        clockObject: &Clock,
        ctx: &mut TxContext,
    ) {
        req_helpers::checkCreatedTimeFrom(reqId, clockObject);
        assert!(!storeA.proposedBurn.contains(reqId), EINVALID_REQ_ID);

        let proposer = ctx.sender();
        assert!(proposer != EXECUTED_PLACEHOLDER, EINVALID_PROPOSER);

        let amount = req_helpers::amountFrom(reqId, storeR);
        let tokenIndex = req_helpers::tokenIndexFrom<CoinType>(reqId, storeR);
        storeA.proposedBurn.add(reqId, proposer);

        utils::joinCoins<CoinType>(coinList, amount, &mut storeA.burningCoins, tokenIndex, ctx);
        event::emit(TokenBurnProposed{ reqId, proposer });
    }

    public entry fun executeBurn<CoinType>(
        reqId: vector<u8>,
        r: vector<vector<u8>>,
        yParityAndS: vector<vector<u8>>,
        executors: vector<vector<u8>>,
        exeIndex: u64,
        fbtcConfig: &mut AccessConfig,
        treasuryCapManager: &mut TreasuryCapManager,
        storeA: &mut AtomicMintStorage,
        storeP: &mut PermissionsStorage,
        storeR: &ReqHelpersStorage,
        clockObject: &Clock,
        ctx: &mut TxContext,
    ) {
        let proposer = storeA.proposedBurn[reqId];
        assert!(proposer != EXECUTED_PLACEHOLDER, EINVALID_REQ_ID);

        let message = req_helpers::msgFromReqSigningMessage(reqId);
        permissions::checkMultiSignatures(
            message, r, yParityAndS, executors, exeIndex, clockObject, storeP,
        );

        *storeA.proposedBurn.borrow_mut(reqId) = EXECUTED_PLACEHOLDER;

        let amount = req_helpers::amountFrom(reqId, storeR);
        let tokenIndex = req_helpers::tokenIndexFrom<CoinType>(reqId, storeR);

        let coinInside = storeA.burningCoins.borrow_mut(tokenIndex);
        let coinBurned = coin::split(coinInside, amount, ctx);

        burn(
            coinBurned, treasuryCapManager, 
            storeA.burnerCaps.borrow(tokenIndex), fbtcConfig
        );
        event::emit(TokenBurnExecuted{ reqId, proposer });
    }

    public entry fun cancelBurn<CoinType>(
        reqId: vector<u8>,
        storeA: &mut AtomicMintStorage,
        storeR: &ReqHelpersStorage,
        clockObject: &Clock,
        ctx: &mut TxContext,
    ) {
        let proposer = storeA.proposedBurn[reqId];
        assert!(proposer != EXECUTED_PLACEHOLDER, EINVALID_REQ_ID);
        assert!(
            clock::timestamp_ms(clockObject) / 1000 > req_helpers::createdTimeFrom(reqId)
            + EXPIRE_PERIOD(), EWAIT_UNTIL_EXPIRED
        );

        storeA.proposedBurn.remove(reqId);

        let amount = req_helpers::amountFrom(reqId, storeR);
        let tokenIndex = req_helpers::tokenIndexFrom<CoinType>(reqId, storeR);

        let coinInside = storeA.burningCoins.borrow_mut(tokenIndex);
        let coinCancelled: Coin<CoinType> = coin::split(coinInside, amount, ctx);

        transfer::public_transfer(coinCancelled, proposer);
        event::emit(TokenBurnCancelled{ reqId, proposer });
    }

}