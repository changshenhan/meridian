// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BatchSettler} from "../src/BatchSettler.sol";
import {ChallengeTestHelper} from "./ChallengeTestHelper.sol";

/// S-11a：BatchSettler 生产化 —— operator 守卫、延迟 claim（原生 ETH）、完整挑战流
/// （漏单/低付欺诈证明 + 债券罚没 + void + 退款）。
/// `epochs()` getter 返回 10 元组（net[]/claimed 被跳过）：
/// [0]commitmentRoot [1]revocationRoot [2]bondedAmount [3]settlementFunded [4]settledAt
/// [5]nettingRoot [6]committed [7]settled [8]challenged [9]voided。
contract BatchSettlerTest is Test, ChallengeTestHelper {
    BatchSettler internal bs;
    /// S-50：挑战押金（部署期构造参数，immutable）。本套件沿用 S-38 的参考值；非缺省值
    /// 的端到端证明见 `test_challenge_bond_is_a_deployment_parameter`。缓存进状态变量
    /// （setUp 读一次）——不能写在 `{value: bs.challengeBond()}` 里，value 表达式里的
    /// 外部 getter 调用会吃掉 vm.prank / vm.expectRevert 的"下一次调用"预期，导致
    /// msg.sender 漂移 / 预期落空。
    uint256 internal challengeBond;
    uint256 internal constant CHALLENGE_BOND = 0.1 ether;
    uint256 internal constant EPOCH = 1;
    uint256 internal constant BOND = 1 ether;
    address internal constant CHALLENGER = address(0xC0FFEE);
    bytes32 internal constant REVOCATION_ROOT = keccak256("revocation-root");

    function setUp() public {
        // operator = 测试合约自身（可直呼 commit/settle）。asset = address(0) → 原生 ETH（v2 行为）。
        bs = new BatchSettler(address(this), address(0), CHALLENGE_BOND);
        // S-38：挑战者要实际押入挑战押金，显式预注资（不依赖 foundry 默认余额）。
        vm.deal(CHALLENGER, 10 ether);
        challengeBond = bs.challengeBond();
    }

    /// 测试合约作为 operator 需能接收 void 时的结算资金退款。
    receive() external payable {}

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
            category: bytes32(0x4444444444444444444444444444444444444444444444444444444444444444),
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
            (uint256 accepted, bytes32[] memory siblings) = proofFor(leaves, i);
            proofs[i] = ProofBundle(seqs[i], i, accepted, siblings);
        }
    }

    function _settleWith(BatchSettler.NetInstruction[] memory net) internal {
        bs.settle{value: _sum(net)}(EPOCH, net, keccak256(abi.encode(net)));
    }

    function _sum(BatchSettler.NetInstruction[] memory net) internal pure returns (uint256 s) {
        for (uint256 i = 0; i < net.length; i++) {
            s += net[i].amount;
        }
    }

    /// 解构 `epochs()` 10 元组为命名变量。
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

    // ------------------------------------------------------------------ S-38 挑战押金 helper

    /// S-38：提交押金发起将被驳回的挑战 —— 断言 ChallengeRejected 事件 + 押金全额销毁
    /// （address(0)，任何一方不可取回）+ epoch 状态零改动（不置 challenged/voided、运营者
    /// 债券与结算资金原封、合约余额进出相抵）。
    function _challengeRejected(BatchSettler.FraudProof memory fp, uint8 reason) internal {
        (, , uint256 bondedBefore, uint256 fundedBefore, , , , , , ) = _epochView(EPOCH);
        uint256 challengerBefore = CHALLENGER.balance;
        uint256 contractBefore = address(bs).balance;
        uint256 burnBefore = address(0).balance;

        vm.expectEmit();
        emit BatchSettler.ChallengeRejected(EPOCH, CHALLENGER, reason);
        vm.prank(CHALLENGER);
        bs.challenge{value: challengeBond}(EPOCH, fp);

        assertEq(address(0).balance, burnBefore + challengeBond, "bond burned");
        assertEq(address(bs).balance, contractBefore, "contract balance in == out");
        assertEq(CHALLENGER.balance, challengerBefore - challengeBond, "bond forfeited");
        (, , uint256 bondedAfter, uint256 fundedAfter, , , , bool settled, bool challenged, bool voided)
            = _epochView(EPOCH);
        assertEq(bondedAfter, bondedBefore, "operator bond untouched");
        assertEq(fundedAfter, fundedBefore, "settlement fund untouched");
        assertTrue(settled);
        assertFalse(challenged, "rejected challenge must not mark epoch challenged");
        assertFalse(voided, "rejected challenge must not void epoch");
    }

    // ------------------------------------------------------------------ S-50 押金参数化

    /// S-50：押金为部署期构造参数。零押金部署等于静默回退到 S-38 之前的垃圾挑战面 →
    /// 构造期 fail-fast（`ZeroChallengeBond`）。
    function test_constructor_rejects_zero_challenge_bond() public {
        vm.expectRevert(BatchSettler.ZeroChallengeBond.selector);
        new BatchSettler(address(this), address(0), 0);
    }

    /// 审计加固：operator 零地址 = commit/settle 恒 NotOperator（自 DoS），构造期挡下。
    /// asset 零地址是合法哨兵（ETH 模式），对照断言防误伤。
    function test_constructor_rejects_zero_operator() public {
        vm.expectRevert(BatchSettler.ZeroOperator.selector);
        new BatchSettler(address(0), address(0), 1 ether);
        // asset 零地址（ETH 模式）不受影响，正常部署。
        new BatchSettler(address(this), address(0), 1 ether);
    }

    /// S-50：非缺省押金端到端 —— 参数不是摆设，金额真进了入场闸与成功路径赔付
    /// （押金原额退回 + 运营者债券罚没一笔给挑战者），且 epoch voided 后 claim 拒绝。
    function test_challenge_bond_is_a_deployment_parameter() public {
        uint256 customBond = 0.37 ether;
        BatchSettler custom = new BatchSettler(address(this), address(0), customBond);
        assertEq(custom.challengeBond(), customBond);

        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        custom.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT);
        custom.settle{value: 0}(EPOCH, _emptyNet(), keccak256(abi.encode(_emptyNet())));

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: ips});

        uint256 challengerBefore = CHALLENGER.balance;
        vm.prank(CHALLENGER);
        custom.challenge{value: customBond}(EPOCH, fp);
        // 押金原额退回（净增 0），净增 = 运营者债券罚没。
        assertEq(CHALLENGER.balance, challengerBefore + BOND, "bond payout uses custom");
        (, , uint256 bondedAmount, uint256 settlementFunded, , , , , , bool voided) =
            _epochViewOn(custom, EPOCH);
        assertEq(bondedAmount, 0);
        assertEq(settlementFunded, 0);
        assertTrue(voided);

        // 缺省押金的 call 在参数化部署上必拒（入场前 revert，无押金风险）。用新 epoch ——
        // EPOCH 已 voided，挑战闸会先撞 EpochAlreadyChallenged 而轮不到金额检查。
        custom.commit{value: BOND}(2, root, REVOCATION_ROOT);
        custom.settle{value: 0}(2, _emptyNet(), keccak256(abi.encode(_emptyNet())));
        vm.expectRevert(BatchSettler.WrongChallengeBond.selector);
        custom.challenge{value: CHALLENGE_BOND}(2, fp);
    }

    /// `_epochView` 的任意部署版本（S-50 参数化用例对第二个 settler 断言 epoch 状态）。
    function _epochViewOn(BatchSettler target, uint256 epochId)
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
        ) = target.epochs(epochId);
    }

    // ------------------------------------------------------------------ commit / operator

    function test_commit_requires_operator() public {
        vm.deal(address(0xBEEF), BOND);
        vm.prank(address(0xBEEF));
        vm.expectRevert(BatchSettler.NotOperator.selector);
        bs.commit{value: BOND}(EPOCH, keccak256("root"), REVOCATION_ROOT);
    }

    function test_commit_records_bond_and_revocation_root() public {
        bytes32 root = keccak256("epoch-1");
        vm.expectEmit();
        emit BatchSettler.Commit(EPOCH, root, REVOCATION_ROOT, BOND);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT);

        (
            bytes32 commitmentRoot,
            bytes32 revocationRoot,
            uint256 bondedAmount,,,,
            bool committed,,,
        ) = _epochView(EPOCH);
        assertEq(commitmentRoot, root);
        assertEq(revocationRoot, REVOCATION_ROOT);
        assertEq(bondedAmount, BOND);
        assertTrue(committed);
    }

    function test_commit_twice_reverts() public {
        bs.commit(EPOCH, keccak256("a"), REVOCATION_ROOT);
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.EpochAlreadyCommitted.selector, EPOCH));
        bs.commit(EPOCH, keccak256("b"), REVOCATION_ROOT);
    }

    // ------------------------------------------------------------------ settle

    function test_settle_requires_operator() public {
        bs.commit(EPOCH, keccak256("root"), REVOCATION_ROOT);
        BatchSettler.NetInstruction[] memory n = _net();
        vm.prank(address(0xBEEF));
        vm.expectRevert(BatchSettler.NotOperator.selector);
        bs.settle(EPOCH, n, keccak256(abi.encode(n)));
    }

    function test_settle_matches_netting_root_and_funds() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT);
        BatchSettler.NetInstruction[] memory n = _net();
        bytes32 nettingRoot = keccak256(abi.encode(n));

        vm.expectEmit();
        emit BatchSettler.Settled(EPOCH, nettingRoot, 2);
        _settleWith(n);

        (,,,,,, bool committed, bool settled, bool challenged, bool voided) = _epochView(EPOCH);
        assertTrue(settled);
    }

    function test_settle_insufficient_funding_reverts() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT);
        BatchSettler.NetInstruction[] memory n = _net(); // Σ = 300
        vm.expectRevert(BatchSettler.InsufficientSettlementFunding.selector);
        bs.settle{value: 299}(EPOCH, n, keccak256(abi.encode(n)));
    }

    function test_settle_wrong_root_reverts() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT);
        vm.expectRevert(BatchSettler.WrongNettingRoot.selector);
        bs.settle{value: 300}(EPOCH, _net(), keccak256("wrong"));
    }

    function test_settle_unknown_epoch_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.EpochUnknown.selector, 999));
        bs.settle(999, _net(), keccak256("x"));
    }

    function test_settle_twice_reverts() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT);
        BatchSettler.NetInstruction[] memory n = _net();
        _settleWith(n);
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.EpochAlreadySettled.selector, EPOCH));
        _settleWith(n);
    }

    // ------------------------------------------------------------------ claim

    function test_claim_after_window_pays_recipient() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT);
        BatchSettler.NetInstruction[] memory n = _net(); // [A1:100, A2:200]
        _settleWith(n);
        vm.warp(block.timestamp + bs.CHALLENGE_WINDOW() + 1);

        uint256 before = address(0xA1).balance;
        vm.expectEmit();
        emit BatchSettler.Claimed(EPOCH, address(0xA1), 100);
        bs.claim(EPOCH, 0);
        assertEq(address(0xA1).balance, before + 100);
    }

    function test_claim_before_window_reverts() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT);
        _settleWith(_net());
        // 仍在窗口内（未 warp）
        vm.expectRevert(BatchSettler.ChallengeWindowOpen.selector);
        bs.claim(EPOCH, 0);
    }

    function test_claim_double_reverts() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT);
        _settleWith(_net());
        vm.warp(block.timestamp + bs.CHALLENGE_WINDOW() + 1);
        bs.claim(EPOCH, 0);
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.AlreadyClaimed.selector, EPOCH, 0));
        bs.claim(EPOCH, 0);
    }

    function test_claim_out_of_bounds_reverts() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT);
        _settleWith(_net());
        vm.warp(block.timestamp + bs.CHALLENGE_WINDOW() + 1);
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.NetIndexOutOfBounds.selector, EPOCH, 5));
        bs.claim(EPOCH, 5);
    }

    function test_claim_unknown_epoch_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.EpochUnknown.selector, 777));
        bs.claim(777, 0);
    }

    // ------------------------------------------------------------------ challenge: missing-recipient (kind 1)

    /// 承诺里包含收款人 R 的意图，net[] 却漏掉 R → 欺诈，债券罚没 + voided + claim 拒绝。
    function test_challenge_missing_recipient_slashes_bond() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT);

        // 欺诈结算：net 只含另一收款人（漏掉 B1）。
        BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](1);
        net[0] = BatchSettler.NetInstruction({recipient: address(0xB9), amount: 0});
        _settleWith(net);

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: ips});

        uint256 challengerBefore = CHALLENGER.balance;
        uint256 operatorBefore = address(this).balance;

        vm.prank(CHALLENGER);
        bs.challenge{value: challengeBond}(EPOCH, fp);

        // 净得 = 运营者债券（押金原额退回，一笔 call 结清）。
        assertEq(CHALLENGER.balance, challengerBefore + BOND, "bond to challenger");
        assertEq(address(bs).balance, 0, "contract drained on success");
        assertEq(address(this).balance, operatorBefore, "no settlement fund to refund (net=0)");
        (,,,,,, bool committed, bool settled, bool challenged, bool voided) = _epochView(EPOCH);
        assertTrue(settled);
        assertTrue(challenged);
        assertTrue(voided);

        // voided → claim 拒绝
        vm.warp(block.timestamp + bs.CHALLENGE_WINDOW() + 1);
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.EpochVoided.selector, EPOCH));
        bs.claim(EPOCH, 0);
    }

    /// 结算资金退款：net = [B9:100]，settlementFunded=100；挑战成功 → 运营者拿回 100。
    function test_challenge_refunds_settlement_fund_to_operator() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT);

        // 欺诈结算：把 B1 的 100 记给 B9（漏 B1），net 有资金。
        BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](1);
        net[0] = BatchSettler.NetInstruction({recipient: address(0xB9), amount: 100});
        _settleWith(net);

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: ips});

        uint256 operatorBefore = address(this).balance;
        vm.prank(CHALLENGER);
        bs.challenge{value: challengeBond}(EPOCH, fp);
        assertEq(address(this).balance, operatorBefore + 100, "settlement fund refunded");
    }

    /// 收款人确实在 net[] → 不是漏单：押金没收、epoch 不动（S-38 驳回即没收）。
    function test_challenge_missing_recipient_rejected_slashes_bond() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT);

        BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](1);
        net[0] = BatchSettler.NetInstruction({recipient: address(0xB1), amount: 100});
        _settleWith(net);

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: ips});

        _challengeRejected(fp, uint8(BatchSettler.RejectReason.NotFraud));
    }

    // ------------------------------------------------------------------ challenge: under-payment (kind 2)

    /// 单笔意图 > net[R].amount → 低付。
    function test_challenge_underpayment_single_succeeds() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT);

        // 低付：B1 真实 100，net 只记 50。
        BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](1);
        net[0] = BatchSettler.NetInstruction({recipient: address(0xB1), amount: 50});
        _settleWith(net);

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 2, targetNetIndex: 0, intents: ips});

        vm.prank(CHALLENGER);
        bs.challenge{value: challengeBond}(EPOCH, fp);
        (,,,,,, bool committed, bool settled, bool challenged, bool voided) = _epochView(EPOCH);
        assertTrue(settled);
        assertTrue(challenged);
        assertTrue(voided);
    }

    /// 多笔同收款人子集和 > net[R].amount → 低付。
    function test_challenge_underpayment_multi_succeeds() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](2);
        intents[0] = _intent(1, address(0xB1), 60, dh);
        intents[1] = _intent(2, address(0xB1), 70, dh);
        uint64[] memory seqs = new uint64[](2);
        seqs[0] = 1;
        seqs[1] = 2;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT);

        // 真实 Σ=130，net 只记 100。
        BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](1);
        net[0] = BatchSettler.NetInstruction({recipient: address(0xB1), amount: 100});
        _settleWith(net);

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](2);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        ips[1] = toIntentProof(intents[1], proofs[1]);
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 2, targetNetIndex: 0, intents: ips});

        vm.prank(CHALLENGER);
        bs.challenge{value: challengeBond}(EPOCH, fp);
        (,,,,,, bool committed, bool settled, bool challenged, bool voided) = _epochView(EPOCH);
        assertTrue(settled);
        assertTrue(challenged);
        assertTrue(voided);
    }

    /// 子集和 ≤ net[R].amount → 非低付（多付不可证，出界）：押金没收、epoch 不动。
    function test_challenge_underpayment_rejected_slashes_bond() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 60, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT);

        // B1 真实 60，net 记 100（多付，非低付）→ 挑战失败。
        BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](1);
        net[0] = BatchSettler.NetInstruction({recipient: address(0xB1), amount: 100});
        _settleWith(net);

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 2, targetNetIndex: 0, intents: ips});

        _challengeRejected(fp, uint8(BatchSettler.RejectReason.NotFraud));
    }

    /// 防假阳性 #2：低付子集跨收款人（B2 的意图 targeting net[B1]）→ 驳回（押金没收）。
    function test_challenge_cross_recipient_subset_rejected_slashes_bond() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](2);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        intents[1] = _intent(2, address(0xB2), 100, dh);
        uint64[] memory seqs = new uint64[](2);
        seqs[0] = 1;
        seqs[1] = 2;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT);

        // net：B1:100, B2:0（B2 真实应 100，但挑战者 targeting net[B1] 并混入 B2 意图）。
        BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](2);
        net[0] = BatchSettler.NetInstruction({recipient: address(0xB1), amount: 100});
        net[1] = BatchSettler.NetInstruction({recipient: address(0xB2), amount: 0});
        _settleWith(net);

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](2);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        ips[1] = toIntentProof(intents[1], proofs[1]);
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 2, targetNetIndex: 0, intents: ips});

        _challengeRejected(fp, uint8(BatchSettler.RejectReason.BadFraudKind));
    }

    /// 防假阳性 #1：同一笔意图在低付子集里重复计入 → 驳回（押金没收）。
    function test_challenge_duplicate_intent_rejected_slashes_bond() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT);

        BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](1);
        net[0] = BatchSettler.NetInstruction({recipient: address(0xB1), amount: 100});
        _settleWith(net);

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](2);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        ips[1] = toIntentProof(intents[0], proofs[0]); // 同一笔重复
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 2, targetNetIndex: 0, intents: ips});

        _challengeRejected(fp, uint8(BatchSettler.RejectReason.DuplicateIntent));
    }

    // ------------------------------------------------------------------ challenge: inclusion adversarial

    function test_challenge_wrong_leaf_index_rejected_slashes_bond() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT);
        _settleWith(_emptyNet());

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        ips[0].leafIndex = 5; // 篡改叶索引 → 根不匹配
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: ips});

        _challengeRejected(fp, uint8(BatchSettler.RejectReason.BadInclusionProof));
    }

    function test_challenge_leaf_index_out_of_bounds_rejected_slashes_bond() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT);
        _settleWith(_emptyNet());

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        ips[0].acceptedCount = 0; // 叶索引 >= acceptedCount → 防御拒绝
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: ips});

        _challengeRejected(fp, uint8(BatchSettler.RejectReason.BadInclusionProof));
    }

    function test_challenge_wrong_accepted_count_rejected_slashes_bond() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](2);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        intents[1] = _intent(2, address(0xB1), 50, dh);
        uint64[] memory seqs = new uint64[](2);
        seqs[0] = 1;
        seqs[1] = 2;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT);
        _settleWith(_emptyNet());

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        ips[0].acceptedCount = 3; // 深度不匹配 → 防御拒绝（预检）
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: ips});

        _challengeRejected(fp, uint8(BatchSettler.RejectReason.BadInclusionProof));
    }

    function test_challenge_fabricated_intent_rejected_slashes_bond() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT);
        _settleWith(_emptyNet());

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        ips[0].amount = 101; // 篡改金额 → 重算 hash 不同 → 非已提交意图 → 包含失败
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: ips});

        _challengeRejected(fp, uint8(BatchSettler.RejectReason.BadInclusionProof));
    }

    // ------------------------------------------------------------------ challenge: window / kind / double

    function test_challenge_after_window_reverts() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT);
        _settleWith(_net());
        vm.warp(block.timestamp + bs.CHALLENGE_WINDOW() + 1);

        vm.expectRevert(BatchSettler.ChallengeWindowClosed.selector);
        bs.challenge(EPOCH, _emptyFraud());
    }

    function test_challenge_double_reverts() public {
        // 先制造一次成功的挑战（漏单欺诈）。
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT);
        _settleWith(_emptyNet());

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: ips});

        vm.prank(CHALLENGER);
        bs.challenge{value: challengeBond}(EPOCH, fp); // 第一次成功

        vm.expectRevert(abi.encodeWithSelector(BatchSettler.EpochAlreadyChallenged.selector, EPOCH));
        bs.challenge(EPOCH, fp); // 第二次拒绝
    }

    function test_challenge_bad_kind_rejected_slashes_bond() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT);
        _settleWith(_emptyNet());

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 3, targetNetIndex: 0, intents: ips});

        _challengeRejected(fp, uint8(BatchSettler.RejectReason.BadFraudKind));
    }

    function test_challenge_unknown_epoch_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.EpochUnknown.selector, 777));
        bs.challenge(777, _emptyFraud());
    }

    /// S-38：意图数为 0 / 超上界是押金入场后的"实质验证失败"（gas 上界守卫）→ 驳回没收。
    function test_challenge_empty_intents_rejected_slashes_bond() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT);
        _settleWith(_net());
        _challengeRejected(_emptyFraud(), uint8(BatchSettler.RejectReason.TooManyIntents));
    }

    /// S-38：押金金额不等（少付/多付）→ 押金入场前 revert（WrongChallengeBond），无押金风险。
    function test_challenge_wrong_bond_value_reverts() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT);
        _settleWith(_net());
        uint256 contractBefore = address(bs).balance;

        vm.prank(CHALLENGER);
        vm.expectRevert(BatchSettler.WrongChallengeBond.selector);
        bs.challenge{value: challengeBond - 1}(EPOCH, _emptyFraud());
        vm.prank(CHALLENGER);
        vm.expectRevert(BatchSettler.WrongChallengeBond.selector);
        bs.challenge{value: challengeBond + 1}(EPOCH, _emptyFraud());

        assertEq(address(bs).balance, contractBefore, "no bond escrowed on wrong value");
    }

    /// S-38：驳回不消耗挑战权 —— 一次失败挑战后，同一 epoch 仍可被合法欺诈证明挑战成功
    /// （押金 + 运营者债券全给挑战者，epoch 才置 challenged/voided）。
    function test_challenge_rejected_then_valid_challenge_succeeds() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT);

        // 欺诈结算：net 只含 B9（漏掉 B1）。
        BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](1);
        net[0] = BatchSettler.NetInstruction({recipient: address(0xB9), amount: 0});
        _settleWith(net);

        // 第一次：伪造意图（amount 篡改 → 包含失败）→ 驳回没收，epoch 不动。
        BatchSettler.IntentProof[] memory badIps = new BatchSettler.IntentProof[](1);
        badIps[0] = toIntentProof(intents[0], proofs[0]);
        badIps[0].amount = 101;
        _challengeRejected(
            BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: badIps}),
            uint8(BatchSettler.RejectReason.BadInclusionProof)
        );

        // 第二次：真实证明 → 挑战成功，押金 + 运营者债券一并结清。
        BatchSettler.IntentProof[] memory goodIps = new BatchSettler.IntentProof[](1);
        goodIps[0] = toIntentProof(intents[0], proofs[0]);
        uint256 challengerBefore = CHALLENGER.balance;

        vm.prank(CHALLENGER);
        bs.challenge{value: challengeBond}(
            EPOCH, BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: goodIps})
        );

        // 净得 = 运营者债券（两次押金：第一次已没收，第二次原额退回）。
        assertEq(CHALLENGER.balance, challengerBefore + BOND, "bond to challenger, bond returned");
        assertEq(address(bs).balance, 0, "contract drained");
        (,,,,,, , bool settled, bool challenged, bool voided) = _epochView(EPOCH);
        assertTrue(settled);
        assertTrue(challenged);
        assertTrue(voided);
    }

    // ------------------------------------------------------------------ shared fixtures

    function _net() internal pure returns (BatchSettler.NetInstruction[] memory n) {
        n = new BatchSettler.NetInstruction[](2);
        n[0] = BatchSettler.NetInstruction({recipient: address(0xA1), amount: 100});
        n[1] = BatchSettler.NetInstruction({recipient: address(0xA2), amount: 200});
    }

    function _emptyNet() internal pure returns (BatchSettler.NetInstruction[] memory n) {
        n = new BatchSettler.NetInstruction[](0);
    }

    function _emptyFraud() internal pure returns (BatchSettler.FraudProof memory fp) {
        BatchSettler.IntentProof[] memory none = new BatchSettler.IntentProof[](0);
        fp = BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: none});
    }
}
