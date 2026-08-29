// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BatchSettler} from "../src/BatchSettler.sol";
import {ChallengeTestHelper} from "./ChallengeTestHelper.sol";
import {MockUSDC} from "./MockUSDC.sol";

/// S-28：资产参数化 —— ERC-20（USDC）结算路径。
/// 覆盖：settle `transferFrom` 拉款 / ETH 禁入 / claim 付 token / 挑战退款按 token 原路退 /
/// 债券恒原生 ETH / 黑名单（转账失败）语义。净额结构与欺诈证明机制与 ETH 模式共用
///（由 BatchSettler.t.sol 的既有套件覆盖 —— asset=address(0) 逐字节保留 v2 行为）。
contract BatchSettlerUsdcTest is Test, ChallengeTestHelper {
    BatchSettler internal bs;
    MockUSDC internal usdc;
    uint256 internal constant EPOCH = 1;
    uint256 internal constant BOND = 1 ether;
    address internal constant CHALLENGER = address(0xC0FFEE);
    bytes32 internal constant REVOCATION_ROOT = keccak256("revocation-root");
    uint256 internal constant MINT = 1_000_000e6; // 1,000,000 USDC

    function setUp() public {
        usdc = new MockUSDC();
        // operator = 测试合约自身；asset = MockUSDC。
        bs = new BatchSettler(address(this), address(usdc));
        usdc.mint(address(this), MINT);
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
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT);
        BatchSettler.NetInstruction[] memory n = _net();

        uint256 opBefore = usdc.balanceOf(address(this));
        _settleUsdc(n);
        assertEq(usdc.balanceOf(address(this)), opBefore - _sum(n), "USDC pulled");
        assertEq(usdc.balanceOf(address(bs)), _sum(n), "held by settler");
        (,, uint256 bonded, uint256 funded,,,, bool settled,,) = _epochView(EPOCH);
        assertEq(bonded, 0, "no bond yet");
        assertEq(funded, _sum(n));
        assertTrue(settled);
    }

    function test_settle_eth_value_reverts_in_token_mode() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT);
        BatchSettler.NetInstruction[] memory n = _net();
        usdc.approve(address(bs), _sum(n));
        vm.expectRevert(BatchSettler.EthValueInTokenMode.selector);
        bs.settle{value: 1 wei}(EPOCH, n, keccak256(abi.encode(n)));
    }

    function test_settle_without_allowance_reverts() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT);
        BatchSettler.NetInstruction[] memory n = _net();
        // 不 approve → transferFrom 失败 → TokenTransferFailed。
        vm.expectRevert(BatchSettler.TokenTransferFailed.selector);
        bs.settle(EPOCH, n, keccak256(abi.encode(n)));
    }

    function test_settle_insufficient_balance_reverts() public {
        // 余额不足（approve 够但 mint 余额 < net 和）→ transferFrom 失败。
        MockUSDC poor = new MockUSDC();
        BatchSettler bsPoor = new BatchSettler(address(this), address(poor));
        poor.mint(address(this), 50e6);
        bsPoor.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT);
        BatchSettler.NetInstruction[] memory n = _net(); // Σ = 300e6 > 50e6
        poor.approve(address(bsPoor), _sum(n));
        vm.expectRevert(BatchSettler.TokenTransferFailed.selector);
        bsPoor.settle(EPOCH, n, keccak256(abi.encode(n)));
    }

    // ------------------------------------------------------------------ claim

    function test_claim_after_window_pays_usdc() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT);
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
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT);
        _settleUsdc(_net());
        vm.warp(block.timestamp + bs.CHALLENGE_WINDOW() + 1);
        bs.claim(EPOCH, 0);
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.AlreadyClaimed.selector, EPOCH, 0));
        bs.claim(EPOCH, 0);
    }

    /// 收款人被真实 USDC 黑名单冻结（transfer revert）→ claim 整笔回滚
    ///（claimed 不置位），资金留在合同；解除黑名单后重试成功。
    function test_claim_blacklisted_recipient_reverts_then_recovers() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT);
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

    /// kind=1 漏单挑战（USDC 模式）：债券（ETH）给挑战者，settlementFunded（USDC）退运营者，
    /// epoch voided，claim 拒绝 —— 双资产分流正确。
    function test_challenge_slashes_eth_bond_and_refunds_usdc() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100e6, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT);

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
        bs.challenge(EPOCH, fp);

        // 债券按 ETH 罚没；结算资金按 USDC 原路退。
        assertEq(CHALLENGER.balance, challengerBefore + BOND, "bond (ETH) to challenger");
        assertEq(usdc.balanceOf(address(this)), opUsdcBefore, "USDC refunded (net=0)");
        assertEq(address(this).balance, opEthBefore, "no ETH refund");
        (,,,,,,, bool settled, bool challenged, bool voided) = _epochView(EPOCH);
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
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT);

        BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](1);
        net[0] = BatchSettler.NetInstruction({recipient: address(0xB9), amount: 100e6});
        _settleUsdc(net);

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: ips});

        uint256 opUsdcBefore = usdc.balanceOf(address(this));
        vm.prank(CHALLENGER);
        bs.challenge(EPOCH, fp);
        assertEq(usdc.balanceOf(address(this)), opUsdcBefore + 100e6, "USDC fund refunded");
    }

    // ------------------------------------------------------------------ ETH 模式回归锚点

    /// asset=address(0) 走原生 ETH —— v2 行为的部署形态（完整回归在 BatchSettler.t.sol）。
    function test_eth_mode_deploy_still_settles_native() public {
        BatchSettler bsEth = new BatchSettler(address(this), address(0));
        bsEth.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT);
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
            uint256 bondedAmount,
            uint256 settlementFunded,
            uint64 settledAt,
            bytes32 nettingRoot,
            bool committed,
            bool settled,
            bool challenged,
            bool voided
        )
    {
        (
            commitmentRoot,
            revocationRoot,
            bondedAmount,
            settlementFunded,
            settledAt,
            nettingRoot,
            committed,
            settled,
            challenged,
            voided
        ) = bs.epochs(epochId);
    }
}
