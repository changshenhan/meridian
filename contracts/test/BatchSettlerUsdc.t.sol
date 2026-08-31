// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BatchSettler} from "../src/BatchSettler.sol";
import {ChallengeTestHelper} from "./ChallengeTestHelper.sol";
import {MockUSDC} from "./MockUSDC.sol";

/// 审计加固测试替身：transfer 恒 revert 的 token（真实 USDC 黑名单语义），覆盖挑战
/// 退款 try/catch 的 revert 冒泡分支（transferFrom 正常，settle 拉款不受影响）。
contract RevertOnTransferToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address, uint256) external pure returns (bool) {
        revert("frozen");
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        if (a < amount) revert("no allowance");
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// S-28：资产参数化 —— ERC-20（USDC）结算路径。
/// 覆盖：settle `transferFrom` 拉款 / ETH 禁入 / claim 付 token / 挑战退款按 token 原路退 /
/// 债券恒原生 ETH / 黑名单（转账失败）语义。净额结构与欺诈证明机制与 ETH 模式共用
///（由 BatchSettler.t.sol 的既有套件覆盖 —— asset=address(0) 逐字节保留 v2 行为）。
contract BatchSettlerUsdcTest is Test, ChallengeTestHelper {
    BatchSettler internal bs;
    MockUSDC internal usdc;
    /// S-38/S-50：挑战押金缓存（setUp 读一次）—— 不能内联进 `{value: ...}` 表达式（外部
    /// getter 会吃掉 vm.prank / vm.expectRevert 的下一次调用预期，见 BatchSettler.t.sol）。
    /// S-50：押金为部署期构造参数，本套件沿用 S-38 参考值。
    uint256 internal challengeBond;
    uint256 internal constant CHALLENGE_BOND = 0.1 ether;
    uint256 internal constant EPOCH = 1;
    uint256 internal constant BOND = 1 ether;
    address internal constant CHALLENGER = address(0xC0FFEE);
    bytes32 internal constant REVOCATION_ROOT = keccak256("revocation-root");
    /// P2-3：接受锚根 / sealedAt 占位（本套件只验资产路径，不消费接受锚面）。
    bytes32 internal constant ACCEPTANCE_ROOT = keccak256("acceptance-root");
    uint64 internal constant SEALED_AT = 1_700_000_000;
    uint256 internal constant MINT = 1_000_000e6; // 1,000,000 USDC

    function setUp() public {
        usdc = new MockUSDC();
        // operator = 测试合约自身；asset = MockUSDC。
        bs = deploySettler(address(this), address(usdc), CHALLENGE_BOND);
        usdc.mint(address(this), MINT);
        // S-38：挑战押金恒为原生 ETH，挑战者预注资。
        vm.deal(CHALLENGER, 10 ether);
        challengeBond = bs.challengeBond();
    }

    // ------------------------------------------------------------------ helpers

    /// token 模式 settle：先 approve 再 settle，且不带任何 ETH。
    function _settleUsdc(BatchSettler.NetInstruction[] memory net) internal {
        usdc.approve(address(bs), _sum(net));
        bs.settle(EPOCH, net, keccak256(abi.encode(net)));
    }

    function _net() internal pure returns (BatchSettler.NetInstruction[] memory n) {
        n = new BatchSettler.NetInstruction[](2);
        n[0] = BatchSettler.NetInstruction({recipient: address(0xA1), amount: 100e6});
        n[1] = BatchSettler.NetInstruction({recipient: address(0xA2), amount: 200e6});
    }

    function _sum(BatchSettler.NetInstruction[] memory net) internal pure returns (uint256 t) {
        for (uint256 i = 0; i < net.length; i++) {
            t += net[i].amount;
        }
    }

    // ------------------------------------------------------------------ helpers

    function _intent(uint64 seq, address recipient, uint64 amount, bytes32 dh)
        internal
        pure
        returns (IntentFields memory)
    {
        return IntentFields({
            agent: bytes20(0x1111111111111111111111111111111111111111),
            delegationHash: dh,
            recipient: bytes20(recipient),
            amount: amount,
            category: bytes32(uint256(0x4444)),
            spendNonce: 7,
            memo: new bytes(0),
            expiresAt: type(uint64).max
        });
    }

    /// 提交一批意图为承诺（根 = sha256 merkle over (seq‖hash)），返回根 + 每条的证明位置。
    function _commitIntents(IntentFields[] memory intents, uint64[] memory seqs)
        internal
        pure
        returns (bytes32 root, ProofBundle[] memory proofs)
    {
        require(intents.length == seqs.length);
        bytes32[] memory leaves = new bytes32[](intents.length);
        proofs = new ProofBundle[](intents.length);
        for (uint256 i = 0; i < intents.length; i++) {
            leaves[i] = leaf(seqs[i], intentHash(intents[i]));
        }
        root = merkleRoot(leaves);
        for (uint256 i = 0; i < intents.length; i++) {
            (uint256 acceptedCount, bytes32[] memory siblings) = proofFor(leaves, i);
            proofs[i] = ProofBundle({
                seq: seqs[i], leafIndex: i, acceptedCount: acceptedCount, siblings: siblings
            });
        }
    }

    // ------------------------------------------------------------------ settle

    function test_settle_pulls_usdc_from_operator() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        BatchSettler.NetInstruction[] memory n = _net();

        uint256 opBefore = usdc.balanceOf(address(this));
        _settleUsdc(n);
        assertEq(usdc.balanceOf(address(this)), opBefore - _sum(n), "USDC pulled");
        assertEq(usdc.balanceOf(address(bs)), _sum(n), "held by settler");
        (,,,,, uint256 bonded, uint256 funded,,) = _epochView(EPOCH);
        (, bool settled,,) = _epochStatus(EPOCH);
        assertEq(bonded, 0, "no bond yet");
        assertEq(funded, _sum(n));
        assertTrue(settled);
    }

    function test_settle_eth_value_reverts_in_token_mode() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        BatchSettler.NetInstruction[] memory n = _net();
        usdc.approve(address(bs), _sum(n));
        vm.expectRevert(BatchSettler.EthValueInTokenMode.selector);
        bs.settle{value: 1 wei}(EPOCH, n, keccak256(abi.encode(n)));
    }

    function test_settle_without_allowance_reverts() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        BatchSettler.NetInstruction[] memory n = _net();
        // 不 approve → transferFrom 失败 → TokenTransferFailed。
        vm.expectRevert(BatchSettler.TokenTransferFailed.selector);
        bs.settle(EPOCH, n, keccak256(abi.encode(n)));
    }

    function test_settle_insufficient_balance_reverts() public {
        // 余额不足（approve 够但 mint 余额 < net 和）→ transferFrom 失败。
        MockUSDC poor = new MockUSDC();
        BatchSettler bsPoor = deploySettler(address(this), address(poor), CHALLENGE_BOND);
        poor.mint(address(this), 50e6);
        bsPoor.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        BatchSettler.NetInstruction[] memory n = _net(); // Σ = 300e6 > 50e6
        poor.approve(address(bsPoor), _sum(n));
        vm.expectRevert(BatchSettler.TokenTransferFailed.selector);
        bsPoor.settle(EPOCH, n, keccak256(abi.encode(n)));
    }

    // ------------------------------------------------------------------ claim

    function test_claim_after_window_pays_usdc() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        BatchSettler.NetInstruction[] memory n = _net();
        _settleUsdc(n);
        vm.warp(block.timestamp + bs.CHALLENGE_WINDOW() + 1);

        uint256 before = usdc.balanceOf(address(0xA1));
        vm.expectEmit();
        emit BatchSettler.Claimed(EPOCH, address(0xA1), 100e6);
        bs.claim(EPOCH, 0);
        assertEq(usdc.balanceOf(address(0xA1)), before + 100e6, "USDC to recipient");
        // 挑战窗口内收不到 ETH —— 窗口前 warp 已过，收款人 ETH 不变。
        assertEq(address(0xA1).balance, 0);
    }

    function test_claim_double_reverts() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        _settleUsdc(_net());
        vm.warp(block.timestamp + bs.CHALLENGE_WINDOW() + 1);
        bs.claim(EPOCH, 0);
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.AlreadyClaimed.selector, EPOCH, 0));
        bs.claim(EPOCH, 0);
    }

    /// 收款人被真实 USDC 黑名单冻结（transfer revert）→ claim 整笔回滚
    ///（claimed 不置位），资金留在合同；解除黑名单后重试成功。
    function test_claim_blacklisted_recipient_reverts_then_recovers() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        BatchSettler.NetInstruction[] memory n = _net();
        _settleUsdc(n);
        vm.warp(block.timestamp + bs.CHALLENGE_WINDOW() + 1);
        usdc.setBlacklist(address(0xA1), true);

        vm.expectRevert(BatchSettler.TokenTransferFailed.selector);
        bs.claim(EPOCH, 0);
        assertEq(usdc.balanceOf(address(bs)), _sum(n), "funds stay in contract");

        // 解除黑名单后重试成功（状态已随 revert 回滚，无脏 claimed 位）。
        usdc.setBlacklist(address(0xA1), false);
        bs.claim(EPOCH, 0);
        assertEq(usdc.balanceOf(address(0xA1)), 100e6, "recovered claim pays");
    }

    // ------------------------------------------------------------------ challenge

    /// kind=1 漏单挑战（USDC 模式）：债券 + 挑战押金（均 ETH）给挑战者，settlementFunded
    /// （USDC）退运营者，epoch voided，claim 拒绝 —— 双资产分流正确（S-38 押金恒 ETH）。
    function test_challenge_slashes_eth_bond_and_refunds_usdc() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100e6, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);

        // 欺诈结算：net 只含另一收款人（漏掉 B1）。
        BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](1);
        net[0] = BatchSettler.NetInstruction({recipient: address(0xB9), amount: 0});
        _settleUsdc(net);

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: ips});

        uint256 challengerBefore = CHALLENGER.balance;
        uint256 opUsdcBefore = usdc.balanceOf(address(this));
        uint256 opEthBefore = address(this).balance;

        vm.prank(CHALLENGER);
        bs.challenge{value: challengeBond}(EPOCH, fp);

        // 债券按 ETH 罚没（押金原额退回，净得 = 债券）；结算资金按 USDC 原路退。
        assertEq(CHALLENGER.balance, challengerBefore + BOND, "bond (ETH) to challenger");
        assertEq(usdc.balanceOf(address(this)), opUsdcBefore, "USDC refunded (net=0)");
        assertEq(address(this).balance, opEthBefore, "no ETH refund");
        (, bool settled, bool challenged, bool voided) = _epochStatus(EPOCH);
        assertTrue(settled);
        assertTrue(challenged);
        assertTrue(voided);

        // voided → claim 拒绝。
        vm.warp(block.timestamp + bs.CHALLENGE_WINDOW() + 1);
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.EpochVoided.selector, EPOCH));
        bs.claim(EPOCH, 0);
    }

    /// kind=1 漏单 + net 有资金：USDC settlementFunded 全额退运营者。
    function test_challenge_refunds_usdc_settlement_fund_to_operator() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100e6, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);

        BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](1);
        net[0] = BatchSettler.NetInstruction({recipient: address(0xB9), amount: 100e6});
        _settleUsdc(net);

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: ips});

        uint256 opUsdcBefore = usdc.balanceOf(address(this));
        vm.prank(CHALLENGER);
        bs.challenge{value: challengeBond}(EPOCH, fp);
        assertEq(usdc.balanceOf(address(this)), opUsdcBefore + 100e6, "USDC fund refunded");
    }

    // ------------------------------------------------------------------ 审计加固：退款 push 失败不阻断挑战（pull 兜底）

    /// 运营者被 token 黑名单冻结（MockUSDC 语义 = transfer 返回 false）→ 退款 push 失败
    /// 不得阻断挑战：epoch 照常 voided、资金留在合约记回 settlementFunded；解除黑名单后
    /// withdrawRefund 拉取兜底。
    function test_challenge_refund_push_failure_pull_fallback_usdc() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100e6, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);

        BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](1);
        net[0] = BatchSettler.NetInstruction({recipient: address(0xB9), amount: 100e6});
        _settleUsdc(net);

        usdc.setBlacklist(address(this), true); // 冻结运营者

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: ips});

        uint256 challengerBefore = CHALLENGER.balance;
        vm.prank(CHALLENGER);
        bs.challenge{value: challengeBond}(EPOCH, fp);

        (,,,,,, uint256 funded,,) = _epochView(EPOCH);
        (,, bool challenged, bool voided) = _epochStatus(EPOCH);
        assertTrue(challenged, "challenge must not be blocked by refund failure");
        assertTrue(voided);
        assertEq(CHALLENGER.balance, challengerBefore + BOND, "bond payout intact");
        assertEq(usdc.balanceOf(address(bs)), 100e6, "USDC retained in contract");
        assertEq(funded, 100e6, "retained refund re-credited");

        // S-58 覆盖缺口：运营者仍被冻结 → withdrawRefund 的 transfer 返回 false →
        // TokenTransferFailed 整笔回滚，记账不丢（revert 冒泡变体见下方 catch 分支测试）。
        vm.expectRevert(BatchSettler.TokenTransferFailed.selector);
        bs.withdrawRefund(EPOCH);
        (,,,,,, uint256 fundedStill,,) = _epochView(EPOCH);
        assertEq(fundedStill, 100e6, "retained accounting intact after failed pull");

        // 拉取兜底：解除黑名单后运营者取回留存量。
        usdc.setBlacklist(address(this), false);
        vm.expectEmit();
        emit BatchSettler.RefundWithdrawn(EPOCH, 100e6);
        bs.withdrawRefund(EPOCH);
        assertEq(usdc.balanceOf(address(bs)), 0, "drained after pull");
        assertEq(usdc.balanceOf(address(this)), MINT, "operator recovered refund");
    }

    /// 真实 USDC 黑名单语义 = transfer revert 冒泡 → try/catch 兜底分支：挑战照常成功，
    /// 资金留存；withdrawRefund 在运营者仍被冻结时 revert（TokenTransferFailed）可重试。
    function test_challenge_refund_reverting_token_catch_branch() public {
        RevertOnTransferToken token = new RevertOnTransferToken();
        BatchSettler bsR = deploySettler(address(this), address(token), CHALLENGE_BOND);
        token.mint(address(this), 1_000e6);

        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100e6, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bsR.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);

        BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](1);
        net[0] = BatchSettler.NetInstruction({recipient: address(0xB9), amount: 100e6});
        token.approve(address(bsR), 100e6);
        bsR.settle(EPOCH, net, keccak256(abi.encode(net)));

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: ips});

        vm.prank(CHALLENGER);
        bsR.challenge{value: challengeBond}(EPOCH, fp); // transfer revert → catch 吸收

        (,,,,,, uint256 funded,,) = bsR.epochs(EPOCH);
        (,, bool challenged, bool voided) = bsR.epochStatus(EPOCH);
        assertTrue(challenged);
        assertTrue(voided);
        assertEq(funded, 100e6, "retained via catch branch");
        assertEq(token.balanceOf(address(bsR)), 100e6);

        // 运营者仍被"冻结" → 拉取失败：revert 原样冒泡（真实 USDC 黑名单语义，
        // 与 claim 的失败路径一致），settlementFunded 记账不丢，解除后可重试。
        vm.expectRevert("frozen");
        bsR.withdrawRefund(EPOCH);
        (,,,,,, uint256 fundedAfter,,) = bsR.epochs(EPOCH);
        assertEq(fundedAfter, 100e6, "retained accounting intact");
    }

    // ------------------------------------------------------------------ ETH 模式回归锚点

    /// asset=address(0) 走原生 ETH —— v2 行为的部署形态（完整回归在 BatchSettler.t.sol）。
    function test_eth_mode_deploy_still_settles_native() public {
        BatchSettler bsEth = deploySettler(address(this), address(0), CHALLENGE_BOND);
        bsEth.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        BatchSettler.NetInstruction[] memory n = new BatchSettler.NetInstruction[](1);
        n[0] = BatchSettler.NetInstruction({recipient: address(0xA1), amount: 1 ether});
        bsEth.settle{value: 1 ether}(EPOCH, n, keccak256(abi.encode(n)));
        vm.warp(block.timestamp + bsEth.CHALLENGE_WINDOW() + 1);
        uint256 before = address(0xA1).balance;
        bsEth.claim(EPOCH, 0);
        assertEq(address(0xA1).balance, before + 1 ether);
        assertEq(address(bsEth).balance, 0);
    }

    // ------------------------------------------------------------------ view

    function _epochView(uint256 epochId)
        internal
        view
        returns (
            bytes32 commitmentRoot,
            bytes32 revocationRoot,
            bytes32 acceptanceRoot,
            uint64 sealedAt,
            uint64 committedAt,
            uint256 bondedAmount,
            uint256 settlementFunded,
            uint64 settledAt,
            bytes32 nettingRoot
        )
    {
        // 同 BatchSettler.t.sol：直接回传 9 元组，避开 coverage 编译（无优化器）栈太深
        //（S-66 读面拆分：13 元组单读恒爆栈，状态位走 _epochStatus）。
        return bs.epochs(epochId);
    }

    function _epochStatus(uint256 epochId)
        internal
        view
        returns (bool committed, bool settled, bool challenged, bool voided)
    {
        return bs.epochStatus(epochId);
    }
}
