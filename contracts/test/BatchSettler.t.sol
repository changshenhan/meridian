// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BatchSettler} from "../src/BatchSettler.sol";
import {DSA} from "../src/DSA.sol";
import {RevocationRegistry} from "../src/RevocationRegistry.sol";
import {ChallengeTestHelper} from "./ChallengeTestHelper.sol";
import {DelegationHelper} from "./DelegationHelper.sol";

/// 审计加固测试替身：可切换收/拒 ETH 的运营者合约（bind/settler 循环依赖用后绑定解）。
contract ToggleOperator {
    BatchSettler internal settler;
    bool public accept;

    function bind(BatchSettler s) external {
        settler = s;
    }

    function setAccept(bool a) external {
        accept = a;
    }

    function commit(uint256 epochId, bytes32 root, bytes32 rr, bytes32 ar, uint64 sealedAt)
        external
        payable
    {
        settler.commit{value: msg.value}(epochId, root, rr, ar, sealedAt);
    }

    function settle(uint256 epochId, BatchSettler.NetInstruction[] calldata net, bytes32 nr)
        external
        payable
    {
        settler.settle{value: msg.value}(epochId, net, nr);
    }

    function withdrawRefund(uint256 epochId) external {
        settler.withdrawRefund(epochId);
    }

    receive() external payable {
        require(accept, "operator refuses eth");
    }
}

/// S-58 覆盖缺口测试替身：无 receive 的收款人合约 —— claim 的 ETH push 返回 false
///（不走 revert 路径，走 `require(ok, "claim transfer failed")`）。
contract RejectEth {}

/// S-58 覆盖缺口测试替身：拒收赔付的挑战者合约 —— 挑战成功路径「押金 + 债券一笔
/// call 给 msg.sender」失败 → require(okPayout) 整笔挑战回滚（挑战者只能伤到自己）。
contract SelfishChallenger {
    BatchSettler internal bs;

    constructor(BatchSettler s) payable {
        bs = s;
    }

    function challenge(uint256 epochId, BatchSettler.FraudProof calldata fp) external {
        bs.challenge{value: address(this).balance}(epochId, fp);
    }

    receive() external payable {
        revert("challenger refuses payout");
    }
}

/// S-11a：BatchSettler 生产化 —— operator 守卫、延迟 claim（原生 ETH）、完整挑战流
/// （漏单/低付欺诈证明 + 债券罚没 + void + 退款）。
/// `epochs()` getter 返回 13 元组（net[]/claimed 被跳过；P2-3 起带接受锚面）：
/// [0]commitmentRoot [1]revocationRoot [2]acceptanceRoot [3]sealedAt [4]committedAt
/// [5]bondedAmount [6]settlementFunded [7]settledAt [8]nettingRoot [9]committed
/// [10]settled [11]challenged [12]voided。
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
    /// P2-3：接受锚根占位（旧测试只关心承诺/撤销面；kind3/kind4 用例自建真树）。
    bytes32 internal constant ACCEPTANCE_ROOT = keccak256("acceptance-root");
    /// P2-3：密封时刻 / kind3/kind4 场景的事件时刻基点（T0）。仅观测面 + 测试时刻基。
    uint64 internal constant SEALED_AT = 1_700_000_000;
    /// P2-3：委托 owner 私钥（DSA 注册 + 撤销 / 绑定签名场景）。
    uint256 internal constant OWNER_PK = 0xA11CE;
    /// P2-3：接受时刻余量（setUp 从合约公开常量读一次——margin 边界用例与守卫共用同一
    /// 数值，合约常量若改，边界用例立即失配；不用 `BatchSettler.ACCEPT_MARGIN` 类型面
    /// 访问，本文件在 via-ir 编译下对该解析失败）。
    uint64 internal margin;

    function setUp() public {
        // operator = 测试合约自身（可直呼 commit/settle）。asset = address(0) → 原生 ETH（v2 行为）。
        bs = deploySettler(address(this), address(0), CHALLENGE_BOND);
        // S-38：挑战者要实际押入挑战押金，显式预注资（不依赖 foundry 默认余额）。
        vm.deal(CHALLENGER, 10 ether);
        challengeBond = bs.challengeBond();
        margin = uint64(bs.ACCEPT_MARGIN());
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

    /// 解构 `epochs()` 9 元组为命名变量（S-66 读面拆分：13 元组单读在 legacy codegen
    /// 恒爆栈，状态位走 [`_epochStatus`]）。
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
        // 直接回传 9 元组：先解构成局部变量再回填命名返回值会把两层局部叠在同一栈帧里，
        // `forge coverage`（禁优化器编译）在此报 stack too deep。
        return bs.epochs(epochId);
    }

    /// 解构 `epochStatus()` 4 状态位（S-66 读面拆分 2/2）。
    function _epochStatus(uint256 epochId)
        internal
        view
        returns (bool committed, bool settled, bool challenged, bool voided)
    {
        return bs.epochStatus(epochId);
    }

    // ------------------------------------------------------------------ S-38 挑战押金 helper

    /// S-38：提交押金发起将被驳回的挑战 —— 断言 ChallengeRejected 事件 + 押金全额销毁
    /// （address(0)，任何一方不可取回）+ epoch 状态零改动（不置 challenged/voided、运营者
    /// 债券与结算资金原封、合约余额进出相抵）。
    function _challengeRejected(BatchSettler.FraudProof memory fp, uint8 reason) internal {
        _challengeRejectedOn(bs, EPOCH, fp, reason);
    }

    /// P2-3：任意部署版本的驳回断言（kind3/kind4 用例对锚定 settler 发起挑战）。
    function _challengeRejectedOn(
        BatchSettler target,
        uint256 epochId,
        BatchSettler.FraudProof memory fp,
        uint8 reason
    ) internal {
        (,,,,, uint256 bondedBefore, uint256 fundedBefore,,) = _epochViewOn(target, epochId);
        uint256 challengerBefore = CHALLENGER.balance;
        uint256 contractBefore = address(target).balance;
        uint256 burnBefore = address(0).balance;

        vm.expectEmit();
        emit BatchSettler.ChallengeRejected(epochId, CHALLENGER, reason);
        vm.prank(CHALLENGER);
        target.challenge{value: challengeBond}(epochId, fp);

        assertEq(address(0).balance, burnBefore + challengeBond, "bond burned");
        assertEq(address(target).balance, contractBefore, "contract balance in == out");
        assertEq(CHALLENGER.balance, challengerBefore - challengeBond, "bond forfeited");
        (,,,,, uint256 bondedAfter, uint256 fundedAfter,,) = _epochViewOn(target, epochId);
        (, bool settled, bool challenged, bool voided) = _epochStatusOn(target, epochId);
        assertEq(bondedAfter, bondedBefore, "operator bond untouched");
        assertEq(fundedAfter, fundedBefore, "settlement fund untouched");
        assertTrue(settled);
        assertFalse(challenged, "rejected challenge must not mark epoch challenged");
        assertFalse(voided, "rejected challenge must not void epoch");
    }

    // ------------------------------------------------------------------ S-50 押金参数化

    /// S-50：押金为部署期构造参数。零押金部署等于静默回退到 S-38 之前的垃圾挑战面 →
    /// 构造期 fail-fast（`ZeroChallengeBond`）。锚依赖给合法值 —— 断言的是押金闸本身
    ///（构造器检查序 operator → bond → anchors，锚缺失会先撞 ZeroAnchor 而非本闸）。
    function test_constructor_rejects_zero_challenge_bond() public {
        DSA dsa = new DSA();
        RevocationRegistry revocations = new RevocationRegistry(dsa);
        vm.expectRevert(BatchSettler.ZeroChallengeBond.selector);
        new BatchSettler(address(this), address(0), 0, dsa, revocations);
    }

    /// 审计加固：operator 零地址 = commit/settle 恒 NotOperator（自 DoS），构造期挡下。
    /// asset 零地址是合法哨兵（ETH 模式），对照断言防误伤。
    function test_constructor_rejects_zero_operator() public {
        DSA dsa = new DSA();
        RevocationRegistry revocations = new RevocationRegistry(dsa);
        vm.expectRevert(BatchSettler.ZeroOperator.selector);
        new BatchSettler(address(0), address(0), 1 ether, dsa, revocations);
        // asset 零地址（ETH 模式）不受影响，正常部署。
        new BatchSettler(address(this), address(0), 1 ether, dsa, revocations);
    }

    /// S-50：非缺省押金端到端 —— 参数不是摆设，金额真进了入场闸与成功路径赔付
    /// （押金原额退回 + 运营者债券罚没一笔给挑战者），且 epoch voided 后 claim 拒绝。
    function test_challenge_bond_is_a_deployment_parameter() public {
        uint256 customBond = 0.37 ether;
        BatchSettler custom = deploySettler(address(this), address(0), customBond);
        assertEq(custom.challengeBond(), customBond);

        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        custom.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
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
        (,,,,, uint256 bondedAmount, uint256 settlementFunded,,) = _epochViewOn(custom, EPOCH);
        (,,, bool voided) = _epochStatusOn(custom, EPOCH);
        assertEq(bondedAmount, 0);
        assertEq(settlementFunded, 0);
        assertTrue(voided);

        // 缺省押金的 call 在参数化部署上必拒（入场前 revert，无押金风险）。用新 epoch ——
        // EPOCH 已 voided，挑战闸会先撞 EpochAlreadyChallenged 而轮不到金额检查。
        custom.commit{value: BOND}(2, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
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
            bytes32 acceptanceRoot,
            uint64 sealedAt,
            uint64 committedAt,
            uint256 bondedAmount,
            uint256 settlementFunded,
            uint64 settledAt,
            bytes32 nettingRoot
        )
    {
        // 同 _epochView：直接回传 9 元组，避开 coverage 编译（无优化器）栈太深。
        return target.epochs(epochId);
    }

    /// `_epochStatus` 的任意部署版本。
    function _epochStatusOn(BatchSettler target, uint256 epochId)
        internal
        view
        returns (bool committed, bool settled, bool challenged, bool voided)
    {
        return target.epochStatus(epochId);
    }

    // ------------------------------------------------------------------ commit / operator

    function test_commit_requires_operator() public {
        vm.deal(address(0xBEEF), BOND);
        vm.prank(address(0xBEEF));
        vm.expectRevert(BatchSettler.NotOperator.selector);
        bs.commit{value: BOND}(
            EPOCH, keccak256("root"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT
        );
    }

    function test_commit_records_bond_and_revocation_root() public {
        bytes32 root = keccak256("epoch-1");
        vm.expectEmit();
        emit BatchSettler.Commit(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT, BOND);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);

        (bytes32 commitmentRoot, bytes32 revocationRoot,,,, uint256 bondedAmount,,,) =
            _epochView(EPOCH);
        (bool committed,,,) = _epochStatus(EPOCH);
        assertEq(commitmentRoot, root);
        assertEq(revocationRoot, REVOCATION_ROOT);
        assertEq(bondedAmount, BOND);
        assertTrue(committed);
    }

    function test_commit_twice_reverts() public {
        bs.commit(EPOCH, keccak256("a"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.EpochAlreadyCommitted.selector, EPOCH));
        bs.commit(EPOCH, keccak256("b"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
    }

    // ------------------------------------------------------------------ settle

    function test_settle_requires_operator() public {
        bs.commit(EPOCH, keccak256("root"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        BatchSettler.NetInstruction[] memory n = _net();
        vm.prank(address(0xBEEF));
        vm.expectRevert(BatchSettler.NotOperator.selector);
        bs.settle(EPOCH, n, keccak256(abi.encode(n)));
    }

    function test_settle_matches_netting_root_and_funds() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        BatchSettler.NetInstruction[] memory n = _net();
        bytes32 nettingRoot = keccak256(abi.encode(n));

        vm.expectEmit();
        emit BatchSettler.Settled(EPOCH, nettingRoot, 2);
        _settleWith(n);

        (bool committed, bool settled, bool challenged, bool voided) = _epochStatus(EPOCH);
        assertTrue(settled);
    }

    function test_settle_insufficient_funding_reverts() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        BatchSettler.NetInstruction[] memory n = _net(); // Σ = 300
        vm.expectRevert(BatchSettler.InsufficientSettlementFunding.selector);
        bs.settle{value: 299}(EPOCH, n, keccak256(abi.encode(n)));
    }

    function test_settle_wrong_root_reverts() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        vm.expectRevert(BatchSettler.WrongNettingRoot.selector);
        bs.settle{value: 300}(EPOCH, _net(), keccak256("wrong"));
    }

    function test_settle_unknown_epoch_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.EpochUnknown.selector, 999));
        bs.settle(999, _net(), keccak256("x"));
    }

    function test_settle_twice_reverts() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        BatchSettler.NetInstruction[] memory n = _net();
        _settleWith(n);
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.EpochAlreadySettled.selector, EPOCH));
        _settleWith(n);
    }

    // ------------------------------------------------------------------ claim

    function test_claim_after_window_pays_recipient() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
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
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        _settleWith(_net());
        // 仍在窗口内（未 warp）
        vm.expectRevert(BatchSettler.ChallengeWindowOpen.selector);
        bs.claim(EPOCH, 0);
    }

    function test_claim_double_reverts() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        _settleWith(_net());
        vm.warp(block.timestamp + bs.CHALLENGE_WINDOW() + 1);
        bs.claim(EPOCH, 0);
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.AlreadyClaimed.selector, EPOCH, 0));
        bs.claim(EPOCH, 0);
    }

    function test_claim_out_of_bounds_reverts() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
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
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);

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
        (bool committed, bool settled, bool challenged, bool voided) = _epochStatus(EPOCH);
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
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);

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
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);

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
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);

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
        (bool committed, bool settled, bool challenged, bool voided) = _epochStatus(EPOCH);
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
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);

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
        (bool committed, bool settled, bool challenged, bool voided) = _epochStatus(EPOCH);
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
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);

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
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);

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
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);

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
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
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
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
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
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
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
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
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
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
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
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
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
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        _settleWith(_emptyNet());

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        // P2-3 起 kind 3/4 是已实现的欺诈种类（专测见 §6.23 节），非法 kind 取 5。
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 5, targetNetIndex: 0, intents: ips});

        _challengeRejected(fp, uint8(BatchSettler.RejectReason.BadFraudKind));
    }

    function test_challenge_unknown_epoch_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.EpochUnknown.selector, 777));
        bs.challenge(777, _emptyFraud());
    }

    /// S-38：意图数为 0 / 超上界是押金入场后的"实质验证失败"（gas 上界守卫）→ 驳回没收。
    function test_challenge_empty_intents_rejected_slashes_bond() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        _settleWith(_net());
        _challengeRejected(_emptyFraud(), uint8(BatchSettler.RejectReason.TooManyIntents));
    }

    /// S-38：押金金额不等（少付/多付）→ 押金入场前 revert（WrongChallengeBond），无押金风险。
    function test_challenge_wrong_bond_value_reverts() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
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
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);

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
        (, bool settled, bool challenged, bool voided) = _epochStatus(EPOCH);
        assertTrue(settled);
        assertTrue(challenged);
        assertTrue(voided);
    }

    // ------------------------------------------------------------------ 审计加固：退款 push 失败不阻断挑战（pull 兜底）

    /// 退款 push 失败（运营者合约拒收 ETH）不得阻断挑战 —— 否则恶意运营者可把 operator
    /// 地址做成 revert 合约审查一切欺诈证明（挑战原子回滚，epoch 永不 voided）。
    /// 断言：挑战照常成功（voided / 债券给挑战者 / 押金退回），结算资金留在合约并记回
    /// settlementFunded；运营者解除拒收后经 withdrawRefund 拉取兜底。
    function test_challenge_refund_push_failure_does_not_block_challenge() public {
        ToggleOperator op = new ToggleOperator();
        BatchSettler target = deploySettler(address(op), address(0), CHALLENGE_BOND);
        op.bind(target);
        op.setAccept(false); // 运营者拒收 ETH

        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);

        BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](1);
        net[0] = BatchSettler.NetInstruction({recipient: address(0xB9), amount: 100});
        op.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        op.settle{value: 100}(EPOCH, net, keccak256(abi.encode(net)));

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: ips});

        uint256 challengerBefore = CHALLENGER.balance;
        vm.prank(CHALLENGER);
        target.challenge{value: challengeBond}(EPOCH, fp);

        // 挑战未被阻断：epoch voided，押金退回 + 债券罚没，结算资金留在合约。
        (,,,,,, uint256 funded,,) = _epochViewOn(target, EPOCH);
        (,, bool challenged, bool voided) = _epochStatusOn(target, EPOCH);
        assertTrue(challenged, "challenge must not be blocked by refund failure");
        assertTrue(voided);
        assertEq(CHALLENGER.balance, challengerBefore + BOND, "bond payout intact");
        assertEq(address(target).balance, 100, "retained refund");
        assertEq(funded, 100, "retained refund re-credited to settlementFunded");

        // 拉取兜底：运营者解除拒收后取回留存量。
        op.setAccept(true);
        op.withdrawRefund(EPOCH);
        assertEq(address(target).balance, 0, "drained after pull");
        (,,,,,, uint256 fundedAfter,,) = _epochViewOn(target, EPOCH);
        assertEq(fundedAfter, 0, "settlementFunded zeroed on pull");
    }

    /// withdrawRefund 只对 voided epoch 开放：正常 epoch 的结算资金归收款人 claim，
    /// 绝不给运营者取回路径（防双花）。
    function test_withdraw_refund_rejects_non_voided_epoch() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        _settleWith(_net());
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.EpochNotVoided.selector, EPOCH));
        bs.withdrawRefund(EPOCH);
    }

    /// voided 但无留存资金（退款 push 当场成功）→ NothingToRefund。
    function test_withdraw_refund_rejects_zero_retained() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        _settleWith(_emptyNet()); // settlementFunded = 0

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        vm.prank(CHALLENGER);
        bs.challenge{value: challengeBond}(
            EPOCH, BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: ips})
        );
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.NothingToRefund.selector, EPOCH));
        bs.withdrawRefund(EPOCH);
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

    // ------------------------------------------------------------------ S-58 分支覆盖缺口收口（forge coverage scan → 负向缝隙）

    /// claim 的 ETH push 失败（收款人合约无 receive）→ require 整笔回滚：claimed 位随
    /// 回滚复位（第二次 claim 仍走转账失败而非 AlreadyClaimed = 可重试语义）、资金留在
    /// 合约、同 epoch 其他行不受污染（收款人自选地址，重试是唯一兜底——审计报告
    /// 「记录在案的已知边界」的行为锚）。
    function test_claim_transfer_failure_rolls_back_claimed_flag() public {
        bs.commit(EPOCH, keccak256("epoch-1"), REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](2);
        net[0] = BatchSettler.NetInstruction({recipient: address(new RejectEth()), amount: 100});
        net[1] = BatchSettler.NetInstruction({recipient: address(0xB2), amount: 200});
        _settleWith(net);
        vm.warp(block.timestamp + bs.CHALLENGE_WINDOW() + 1);

        vm.expectRevert("claim transfer failed");
        bs.claim(EPOCH, 0);
        vm.expectRevert("claim transfer failed");
        bs.claim(EPOCH, 0); // 复位而非卡死在已置位：若 claimed 位被持久化，这里已是 AlreadyClaimed
        assertEq(address(bs).balance, 300, "failed claim retains funds");

        bs.claim(EPOCH, 1);
        assertEq(address(bs).balance, 100, "unrelated row unaffected");
    }

    /// 挑战者合约拒收赔付 → require(okPayout) 整笔挑战回滚：押金随交易退回挑战者、
    /// epoch 状态零改动、仍可被他人挑战。审查方向的反面：这条边只会惩罚挑战者自己，
    /// 不可能被用于阻止 epoch voided。
    function test_challenge_payout_rejection_rolls_back_and_epoch_stays_challengeable() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);

        BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](1);
        net[0] = BatchSettler.NetInstruction({recipient: address(0xB9), amount: 100});
        _settleWith(net); // 漏掉 0xB1 → 诚实 kind1 欺诈证明

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        BatchSettler.FraudProof memory fp =
            BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: ips});

        SelfishChallenger greedy = new SelfishChallenger{value: challengeBond}(bs);
        vm.expectRevert("bond transfer failed");
        greedy.challenge(EPOCH, fp);

        // 整笔回滚：债券 / 结算资金 / epoch 状态全部原位。
        (,,,,, uint256 bondedAmount, uint256 settlementFunded,,) = _epochView(EPOCH);
        (,, bool challenged, bool voided) = _epochStatus(EPOCH);
        assertEq(bondedAmount, BOND);
        assertEq(settlementFunded, 100);
        assertFalse(challenged);
        assertFalse(voided);
        assertEq(address(bs).balance, BOND + 100, "contract untouched");
        assertEq(address(greedy).balance, challengeBond, "bond rolled back to challenger");

        // epoch 仍可被正常挑战者挑战成功。
        vm.prank(CHALLENGER);
        bs.challenge{value: challengeBond}(EPOCH, fp);
        (,, bool challengedAfter, bool voidedAfter) = _epochStatus(EPOCH);
        assertTrue(challengedAfter);
        assertTrue(voidedAfter);
    }

    /// kind1（漏单）携带多条意图 → BadFraudKind。即使每条都是真包含证明也不放行——
    /// 漏单陈述的定义就是单条（`intents.length != 1` 边）。
    function test_kind1_multiple_intents_rejected_slashes_bond() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](2);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        intents[1] = _intent(2, address(0xB1), 120, dh);
        uint64[] memory seqs = new uint64[](2);
        seqs[0] = 1;
        seqs[1] = 2;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);

        BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](1);
        net[0] = BatchSettler.NetInstruction({recipient: address(0xB9), amount: 220});
        _settleWith(net);

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](2);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        ips[1] = toIntentProof(intents[1], proofs[1]);
        _challengeRejected(
            BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: ips}),
            uint8(BatchSettler.RejectReason.BadFraudKind)
        );
    }

    /// kind2 目标行越界（`targetNetIndex >= net.length`）→ NetIndexOutOfBounds 原因码
    /// （驳回 + 押金销毁，不是 revert；进入逐条验证之前就拦下）。
    function test_kind2_target_net_index_out_of_bounds_rejected_slashes_bond() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        _settleWith(_net()); // 2 行，合法目标 0/1

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        _challengeRejected(
            BatchSettler.FraudProof({kind: 2, targetNetIndex: 2, intents: ips}),
            uint8(BatchSettler.RejectReason.NetIndexOutOfBounds)
        );
    }

    /// 低付子集混入伪造意图（不在承诺格）→ BadInclusionProof：子集是逐条包含性校验，
    /// 不是只验第一条；伪造意图同收款人（过 kind2 收款人一致性闸）且不同哈希（过
    /// DuplicateIntent 闸），只能倒在根校验上。
    function test_kind2_fabricated_intent_in_subset_rejected_slashes_bond() public {
        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](2);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        intents[1] = _intent(2, address(0xB1), 120, dh);
        uint64[] memory seqs = new uint64[](2);
        seqs[0] = 1;
        seqs[1] = 2;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);

        // 真实 Σ=220，net 记 50 → 本是真低付；混入伪造意图后整笔驳回。
        BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](1);
        net[0] = BatchSettler.NetInstruction({recipient: address(0xB1), amount: 50});
        _settleWith(net);

        IntentFields memory fake = intents[1];
        fake.delegationHash = keccak256("fabricated");
        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](2);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        ips[1] = toIntentProof(fake, proofs[1]);
        _challengeRejected(
            BatchSettler.FraudProof({kind: 2, targetNetIndex: 0, intents: ips}),
            uint8(BatchSettler.RejectReason.BadInclusionProof)
        );
    }

    /// withdrawRefund 的 push 自身失败（运营者仍拒收 ETH）→ require 整笔回滚：
    /// settlementFunded 记账不丢，解除拒收后同一笔重试成功（push 失败与 pull 成功
    /// 是两条独立覆盖边；push 失败不阻断挑战的语义见上方专项测试）。
    function test_withdraw_refund_push_failure_is_retryable() public {
        ToggleOperator op = new ToggleOperator();
        BatchSettler target = deploySettler(address(op), address(0), CHALLENGE_BOND);
        op.bind(target);
        op.setAccept(false); // 运营者拒收 ETH

        bytes32 dh = keccak256("delegation-1");
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);
        op.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);
        BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](1);
        net[0] = BatchSettler.NetInstruction({recipient: address(0xB9), amount: 100});
        op.settle{value: 100}(EPOCH, net, keccak256(abi.encode(net)));

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(intents[0], proofs[0]);
        vm.prank(CHALLENGER);
        target.challenge{value: challengeBond}(
            EPOCH, BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: ips})
        );
        (,,,,,, uint256 funded,,) = _epochViewOn(target, EPOCH);
        (,, bool challenged, bool voided) = _epochStatusOn(target, EPOCH);
        assertTrue(challenged);
        assertTrue(voided);
        assertEq(funded, 100, "refund push failed -> retained");

        vm.expectRevert("refund transfer failed");
        op.withdrawRefund(EPOCH);
        (,,,,,, uint256 fundedStill,,) = _epochViewOn(target, EPOCH);
        assertEq(fundedStill, 100, "retained accounting intact after failed pull");
        assertEq(address(target).balance, 100);

        op.setAccept(true);
        vm.expectEmit();
        emit BatchSettler.RefundWithdrawn(EPOCH, 100);
        op.withdrawRefund(EPOCH);
        (,,,,,, uint256 fundedAfter,,) = _epochViewOn(target, EPOCH);
        assertEq(fundedAfter, 0, "drained after pull");
    }

    // ------------------------------------------------------------------ P2-3 接受锚（§6.23）

    /// P2-3：kind3/kind4 场景的委托注册（owner = vm.addr(OWNER_PK)，r||s 紧凑签名）。
    function _registerDelegation(DSA dsa) internal returns (address owner, bytes32 dh) {
        owner = vm.addr(OWNER_PK);
        (bytes memory abiBytes, bytes32 delegationHash) = DelegationHelper.buildDelegation(owner);
        (, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, delegationHash);
        dsa.registerDelegation(abiBytes, abi.encodePacked(r, s));
        dh = delegationHash;
    }

    /// P2-3：平行接受树 —— 与承诺树同叶集同序（seq 升序），叶 = acceptanceLeaf(seq, acceptedAt)，
    /// 全批同一接受时刻（单一 acceptedAt 即可锚定 kind3/kind4 的时间下界）。返回根 + 第 0 叶
    /// 兄弟路径（场景均为单意图；两树同叶序 ⇒ 复用同一 leafIndex/acceptedCount，§6.23.1 定夺 6）。
    function _acceptanceTree(uint64[] memory seqs, uint64 acceptedAt)
        internal
        pure
        returns (bytes32 accRoot, bytes32[] memory accSiblings)
    {
        bytes32[] memory accLeaves = new bytes32[](seqs.length);
        for (uint256 i = 0; i < seqs.length; i++) {
            accLeaves[i] = acceptanceLeafOf(seqs[i], acceptedAt);
        }
        accRoot = merkleRoot(accLeaves);
        (, accSiblings) = proofFor(accLeaves, 0);
    }

    /// kind3/kind4 共享半场：单意图承诺 + 平行接受树（锚 `anchorAt`）→ 密封提交 → 结算
    /// 空 net（可罚本体是「已接受」本身，不做 net 命中检查），返回带接受锚路径的证明。
    /// （coverage 模式 legacy codegen 收栈：场景函数只留部署/事件分支的局部变量，先例
    /// _verifyFraudKind1-4 拆分。）
    function _kind34Seal(BatchSettler settler, bytes32 dh, uint64 anchorAt)
        internal
        returns (BatchSettler.IntentProof memory ip)
    {
        IntentFields[] memory intents = new IntentFields[](1);
        intents[0] = _intent(1, address(0xB1), 100, dh);
        uint64[] memory seqs = new uint64[](1);
        seqs[0] = 1;
        (bytes32 root, ProofBundle[] memory proofs) = _commitIntents(intents, seqs);

        (bytes32 accRoot, bytes32[] memory accSiblings) = _acceptanceTree(seqs, anchorAt);
        settler.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, accRoot, SEALED_AT);
        settler.settle{value: 0}(EPOCH, _emptyNet(), keccak256(abi.encode(_emptyNet())));

        ip = toAnchoredIntentProof(intents[0], proofs[0], anchorAt, accSiblings);
    }

    /// kind3 场景：锚定 settler + 已注册委托 →（可选）T0 撤销 → 密封提交（接受树锚
    /// `anchorAt`）。证明声明的接受时刻为 `claimAt`（= anchorAt 即诚实；> anchorAt 即
    /// 回填攻击，被承诺面挡住）。T0 = SEALED_AT：撤销/绑定先于接受发生。
    function _kind3Scenario(uint64 anchorAt, uint64 claimAt, bool revoked)
        internal
        returns (BatchSettler target, BatchSettler.FraudProof memory fp)
    {
        (BatchSettler settler, DSA dsa, RevocationRegistry revocations) =
            deployAnchoredSettler(address(this), address(0), CHALLENGE_BOND);
        (address owner, bytes32 dh) = _registerDelegation(dsa);

        vm.warp(SEALED_AT);
        if (revoked) {
            vm.prank(owner);
            revocations.revoke(dh);
        }

        BatchSettler.IntentProof memory ip = _kind34Seal(settler, dh, anchorAt);
        ip.acceptedAt = claimAt; // 声明面：仅此字段与树锚（anchorAt）不同即回填变体
        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = ip;
        fp = BatchSettler.FraudProof({kind: 3, targetNetIndex: 0, intents: ips});
        target = settler;
    }

    /// kind4 场景：同 kind3 骨架，撤销换成运营者绑定（boundTo = 0 → 不绑，保持未绑定三态）。
    function _kind4Scenario(uint64 acceptedAt, address boundTo)
        internal
        returns (BatchSettler target, BatchSettler.FraudProof memory fp)
    {
        (BatchSettler settler, DSA dsa,) =
            deployAnchoredSettler(address(this), address(0), CHALLENGE_BOND);
        (address owner, bytes32 dh) = _registerDelegation(dsa);

        vm.warp(SEALED_AT);
        if (boundTo != address(0)) {
            vm.prank(owner);
            dsa.bindOperator(dh, boundTo);
        }

        BatchSettler.IntentProof memory ip = _kind34Seal(settler, dh, acceptedAt);
        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = ip;
        fp = BatchSettler.FraudProof({kind: 4, targetNetIndex: 0, intents: ips});
        target = settler;
    }

    /// commit 扩展面：接受锚根 + sealedAt 入 Epoch，committedAt 由合约以链钟写定（§6.23.1
    /// 定夺 5：sealedAt 只进观测面，committedAt 是链上写定的上界锚）。
    function test_commit_records_acceptance_anchor_and_sealed_at() public {
        bytes32 root = keccak256("epoch-1");
        vm.expectEmit();
        emit BatchSettler.Commit(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT, BOND);
        bs.commit{value: BOND}(EPOCH, root, REVOCATION_ROOT, ACCEPTANCE_ROOT, SEALED_AT);

        (,, bytes32 acceptanceRoot, uint64 sealedAt, uint64 committedAt,,,,) = _epochView(EPOCH);
        assertEq(acceptanceRoot, ACCEPTANCE_ROOT);
        assertEq(sealedAt, SEALED_AT);
        assertEq(uint256(committedAt), block.timestamp);
    }

    /// P2-3 定夺 7：kind3/kind4 守卫读面缺依赖（DSA / RevocationRegistry 零地址）→ 构造期
    /// fail-fast（ZeroAnchor）——缺锚等于守卫静默失效面伪装。
    function test_constructor_rejects_zero_anchor() public {
        DSA dsa = new DSA();
        RevocationRegistry revocations = new RevocationRegistry(dsa);
        vm.expectRevert(BatchSettler.ZeroAnchor.selector);
        new BatchSettler(address(this), address(0), 1 ether, DSA(address(0)), revocations);
        vm.expectRevert(BatchSettler.ZeroAnchor.selector);
        new BatchSettler(address(this), address(0), 1 ether, dsa, RevocationRegistry(address(0)));
        // 两锚齐备 → 正常部署（对照）。
        new BatchSettler(address(this), address(0), 1 ether, dsa, revocations);
    }

    /// P2-3 定夺 7：注册表指向另一套 DSA（撤销时刻锚与绑定锚分家）→ 构造期 fail-fast。
    function test_constructor_rejects_dsa_mismatch() public {
        DSA dsa = new DSA();
        RevocationRegistry revocations = new RevocationRegistry(new DSA());
        vm.expectRevert(BatchSettler.DsaMismatch.selector);
        new BatchSettler(address(this), address(0), 1 ether, dsa, revocations);
    }

    /// kind3 正向：撤销后 margin 之外仍被接受 → 债券罚没 + epoch voided。
    function test_kind3_revoked_consumption_slashes_bond() public {
        (BatchSettler target, BatchSettler.FraudProof memory fp) =
            _kind3Scenario(SEALED_AT + 1_000, SEALED_AT + 1_000, true);

        uint256 challengerBefore = CHALLENGER.balance;
        vm.prank(CHALLENGER);
        target.challenge{value: challengeBond}(EPOCH, fp);
        assertEq(CHALLENGER.balance, challengerBefore + BOND, "bond slashed to challenger");
        (, bool challenged,, bool voided) = _epochStatusOn(target, EPOCH);
        assertTrue(challenged);
        assertTrue(voided);
    }

    /// kind3 margin 边界：`revokedAt + margin == acceptedAt` → 欺诈成立（守卫判 `>`，等号
    /// 落在可罚侧——余量之外的第一秒即罚）。
    function test_kind3_margin_boundary_exact_slashes_bond() public {
        (BatchSettler target, BatchSettler.FraudProof memory fp) =
            _kind3Scenario(SEALED_AT + margin, SEALED_AT + margin, true);
        vm.prank(CHALLENGER);
        target.challenge{value: challengeBond}(EPOCH, fp);
        (, bool challenged,, bool voided) = _epochStatusOn(target, EPOCH);
        assertTrue(challenged);
        assertTrue(voided);
    }

    /// kind3 margin 边界（负向）：`acceptedAt = revokedAt + margin − 1` → 余量之内，不罚。
    function test_kind3_margin_boundary_minus_one_rejected() public {
        (BatchSettler target, BatchSettler.FraudProof memory fp) =
            _kind3Scenario(SEALED_AT + margin - 1, SEALED_AT + margin - 1, true);
        _challengeRejectedOn(target, EPOCH, fp, uint8(BatchSettler.RejectReason.NotFraud));
    }

    /// kind3 负向：委托未撤销（revokedAt = 0）→ kind 不成立（押金没收，epoch 不动）。
    function test_kind3_unrevoked_is_not_fraud() public {
        (BatchSettler target, BatchSettler.FraudProof memory fp) =
            _kind3Scenario(SEALED_AT + 1_000, SEALED_AT + 1_000, false);
        _challengeRejectedOn(target, EPOCH, fp, uint8(BatchSettler.RejectReason.NotFraud));
    }

    /// kind3 负向：legacy 哨兵 acceptedAt = 0（旧证据形状）→ 时间守卫恒放行，不构成欺诈
    ///（§6.23.1 定夺 9：零值哨兵语义 = 「接受时刻未知」，绝不因缺锚被反向定罪）。
    function test_kind3_legacy_sentinel_accepted_at_zero_is_not_fraud() public {
        (BatchSettler target, BatchSettler.FraudProof memory fp) = _kind3Scenario(0, 0, true);
        _challengeRejectedOn(target, EPOCH, fp, uint8(BatchSettler.RejectReason.NotFraud));
    }

    /// kind3 负向：回填接受时刻被接受锚挡死（§6.23.1 定夺 8）——树按诚实时刻 anchorAt 承诺，
    /// 证明把 acceptedAt 抬高 1 秒 → 接受叶重算失配 → BadInclusionProof（而非 NotFraud）。
    function test_kind3_backfilled_accepted_at_fails_acceptance_inclusion() public {
        (BatchSettler target, BatchSettler.FraudProof memory fp) =
            _kind3Scenario(SEALED_AT + margin - 1, SEALED_AT + margin, true);
        _challengeRejectedOn(target, EPOCH, fp, uint8(BatchSettler.RejectReason.BadInclusionProof));
    }

    /// kind3 多意图 → BadFraudKind（kind1 同款计数闸；闸先于包含验证，重复同一证明即触发）。
    function test_kind3_multiple_intents_rejected_slashes_bond() public {
        (BatchSettler target, BatchSettler.FraudProof memory single) =
            _kind3Scenario(SEALED_AT + 1_000, SEALED_AT + 1_000, true);

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](2);
        ips[0] = single.intents[0];
        ips[1] = single.intents[0];
        _challengeRejectedOn(
            target,
            EPOCH,
            BatchSettler.FraudProof({kind: 3, targetNetIndex: 0, intents: ips}),
            uint8(BatchSettler.RejectReason.BadFraudKind)
        );
    }

    /// kind4 多意图 → BadFraudKind（kind1/kind3 同款计数闸；闸先于包含验证）。
    function test_kind4_multiple_intents_rejected_slashes_bond() public {
        (BatchSettler target, BatchSettler.FraudProof memory single) =
            _kind4Scenario(SEALED_AT + 1_000, makeAddr("cross-shard-operator"));

        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](2);
        ips[0] = single.intents[0];
        ips[1] = single.intents[0];
        _challengeRejectedOn(
            target,
            EPOCH,
            BatchSettler.FraudProof({kind: 4, targetNetIndex: 0, intents: ips}),
            uint8(BatchSettler.RejectReason.BadFraudKind)
        );
    }

    /// kind4 正向：委托绑定到他方运营者且 boundAt + margin ≤ acceptedAt 仍被本账本接受 →
    /// 罚没（跨分片预算超支的可罚本体，§6.19.1）。
    function test_kind4_cross_shard_consumption_slashes_bond() public {
        (BatchSettler target, BatchSettler.FraudProof memory fp) =
            _kind4Scenario(SEALED_AT + 1_000, makeAddr("cross-shard-operator"));

        uint256 challengerBefore = CHALLENGER.balance;
        vm.prank(CHALLENGER);
        target.challenge{value: challengeBond}(EPOCH, fp);
        assertEq(CHALLENGER.balance, challengerBefore + BOND, "bond slashed to challenger");
        (, bool challenged,, bool voided) = _epochStatusOn(target, EPOCH);
        assertTrue(challenged);
        assertTrue(voided);
    }

    /// kind3 负向（承诺面）：伪造意图（amount 篡改 → 意图哈希变 → 承诺根不匹配）→
    /// BadInclusionProof 在承诺树闸即倒下（接受树不查——双树闸的次序，§6.23.1 定夺 8）。
    /// 接受叶只含 (seq, acceptedAt)，不含金额 ⇒ 金额伪造专倒承诺面。
    function test_kind3_fabricated_intent_fails_commitment_inclusion() public {
        (BatchSettler target, BatchSettler.FraudProof memory fp) =
            _kind3Scenario(SEALED_AT + 1_000, SEALED_AT + 1_000, true);
        fp.intents[0].amount += 1;
        _challengeRejectedOn(target, EPOCH, fp, uint8(BatchSettler.RejectReason.BadInclusionProof));
    }

    /// kind4 负向：回填接受时刻被接受锚挡死（§6.23.1 定夺 8，kind3 同款向量）——树按
    /// 诚实时刻承诺，证明把 acceptedAt 抬高 1 秒 → 接受叶重算失配 → BadInclusionProof。
    function test_kind4_backfilled_accepted_at_fails_acceptance_inclusion() public {
        (BatchSettler target, BatchSettler.FraudProof memory fp) =
            _kind4Scenario(SEALED_AT + margin - 1, makeAddr("cross-shard-operator"));
        fp.intents[0].acceptedAt += 1;
        _challengeRejectedOn(target, EPOCH, fp, uint8(BatchSettler.RejectReason.BadInclusionProof));
    }

    /// kind3 负向：接受树兄弟路径深度错（承诺路径合法先行通过）→ BadInclusionProof
    /// 落在接受树长度闸（两树同深度前提的自校验边）。单意图树深度 = 0（空路径合法），
    /// 伪造 1 个假兄弟使长度 ≠ treeDepth(1)。
    function test_kind3_wrong_acceptance_sibling_depth_fails_acceptance_inclusion() public {
        (BatchSettler target, BatchSettler.FraudProof memory fp) =
            _kind3Scenario(SEALED_AT + 1_000, SEALED_AT + 1_000, true);
        fp.intents[0].acceptanceSiblings = new bytes32[](1);
        fp.intents[0].acceptanceSiblings[0] = keccak256("wrong-sibling");
        _challengeRejectedOn(target, EPOCH, fp, uint8(BatchSettler.RejectReason.BadInclusionProof));
    }

    /// kind4 负向（承诺面）：伪造意图（amount 篡改 → 承诺根不匹配）→ BadInclusionProof
    /// 在承诺树闸即倒下（接受叶不含金额，同 kind3 承诺面向量）。
    function test_kind4_fabricated_intent_fails_commitment_inclusion() public {
        (BatchSettler target, BatchSettler.FraudProof memory fp) =
            _kind4Scenario(SEALED_AT + 1_000, makeAddr("cross-shard-operator"));
        fp.intents[0].amount += 1;
        _challengeRejectedOn(target, EPOCH, fp, uint8(BatchSettler.RejectReason.BadInclusionProof));
    }

    /// kind4 margin 边界：`boundAt + margin == acceptedAt` → 欺诈成立（等号落在可罚侧）。
    function test_kind4_margin_boundary_exact_slashes_bond() public {
        (BatchSettler target, BatchSettler.FraudProof memory fp) =
            _kind4Scenario(SEALED_AT + margin, makeAddr("cross-shard-operator"));
        vm.prank(CHALLENGER);
        target.challenge{value: challengeBond}(EPOCH, fp);
        (, bool challenged,, bool voided) = _epochStatusOn(target, EPOCH);
        assertTrue(challenged);
        assertTrue(voided);
    }

    /// kind4 负向：未绑定（boundAt = 0 ⇔ operatorOf = 零地址）→ fail-open 三态，不罚
    ///（§6.19.2 决策 B 的有意取舍，与聚合器摄取闸同口径）。
    function test_kind4_unbound_is_not_fraud() public {
        (BatchSettler target, BatchSettler.FraudProof memory fp) =
            _kind4Scenario(SEALED_AT + 1_000, address(0));
        _challengeRejectedOn(target, EPOCH, fp, uint8(BatchSettler.RejectReason.NotFraud));
    }

    /// kind4 负向：绑到本运营者自己 = 本分片内的正常委托，非跨分片，kind4 无对象。
    function test_kind4_bound_to_self_operator_is_not_fraud() public {
        (BatchSettler target, BatchSettler.FraudProof memory fp) =
            _kind4Scenario(SEALED_AT + 1_000, address(this));
        _challengeRejectedOn(target, EPOCH, fp, uint8(BatchSettler.RejectReason.NotFraud));
    }

    /// kind4 负向：事件发生在接受之后（acceptedAt < boundAt + margin）→ 余量之内，不罚
    ///（§6.20.1 抽债券向量：绑定时点之后才接受的消费不能被倒算成跨分片欺诈）。
    function test_kind4_event_after_acceptance_is_not_fraud() public {
        (BatchSettler target, BatchSettler.FraudProof memory fp) =
            _kind4Scenario(SEALED_AT - 1, makeAddr("cross-shard-operator"));
        _challengeRejectedOn(target, EPOCH, fp, uint8(BatchSettler.RejectReason.NotFraud));
    }
}
