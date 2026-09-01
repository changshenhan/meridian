// SPDX-License-Identifier: Elastic-0.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BatchSettler} from "../src/BatchSettler.sol";
import {ChallengeTestHelper} from "./ChallengeTestHelper.sol";

/// 审计加固第二轮（四步路径 ②）：invariant fuzz —— 随机调用序列锤状态机不变量。
///
/// Handler 扮演随机化运营者/挑战者：commit 顺序 epoch（随机 1-4 条意图）→ settle
/// （诚实 / 漏单 / 低付三种模式）→ 窗口内挑战（真欺诈证明 / 垃圾挑战）→ warp 过窗
/// 后 claim → releaseBond 退债（S-77 happy path）。锁死三条全局不变量：
///   ① 资金守恒：合约 ETH 余额 == ΣbondedAmount（ghost 净已释放）+ ΣsettlementFunded
///     - Σ已付 claim（handler 的 settle 恒按 Σnet 精确注资，债券/押金/退款/罚没/退债
///     全走 ghost 记账）。release 把债券同时移出 storage 与合约余额，守恒式对
///     退债路径自动闭合——修复前 release 面不存在，本不变量无法暴露滞留缺陷，
///     故另需动作面覆盖（S-77 教训：守恒式"绿"≠生命周期完备）。
///   ② 状态机单调：settled ⇒ committed；challenged ⇒ voided（成功挑战二者同置，
///     驳回永不置位）；voided ⇒ challenged。
///   ③ voided 后 claim 必须拒绝（try/catch 行为断言，绕开 fail_on_revert）。
contract SettlerHandler is Test, ChallengeTestHelper {
    BatchSettler public bs;
    address internal operator = address(0xA11CE);
    address internal challenger = address(0xC0FFEE);

    uint256 internal constant BOND = 1 ether;
    uint256 internal constant DEPOSIT = 0.1 ether;
    uint256 internal constant WINDOW = 6 hours;
    /// P2-3：接受锚根 / sealedAt 占位（handler 只出 kind1/kind2 证明，不消费接受锚面）。
    bytes32 internal constant ACCEPTANCE_ROOT = keccak256("acceptance-root");
    uint64 internal constant SEALED_AT = 1_700_000_000;

    address[3] internal recipients = [address(0xB1), address(0xB2), address(0xB3)];

    struct IntentRec {
        IntentFields fields;
        uint64 seq;
    }

    mapping(uint256 => IntentRec[]) internal committed;
    /// settle 落盘的净额行（claim 记账 + 挑战证明构造的权威副本）。
    mapping(uint256 => BatchSettler.NetInstruction[]) internal netLines;
    mapping(uint256 => uint256) internal settledAtOf;
    /// settle 时注资的原额（挑战成功扣 ghost 用——成功后 storage 已清零，不能再读）。
    mapping(uint256 => uint256) internal fundedOf;
    mapping(uint256 => bool) internal settledEpoch;
    mapping(uint256 => bool) internal voidedEpoch;
    mapping(uint256 => bool) internal releasedEpoch;

    uint256 public epochCount; // 顺序 epochId（0..count-1），不变量可枚举
    uint64 public seqCounter;
    bool public brokenVoidedClaim; // ③ 行为断言的破约旗

    // ① 资金守恒 ghost 记账（与 storage 同步增减）。ghostBondSum 为净额：release 后同步减。
    uint256 public ghostBondSum;
    uint256 public ghostFundedSum;
    uint256 public ghostClaimedSum;

    constructor() {
        bs = deploySettler(operator, address(0), DEPOSIT);
        vm.deal(operator, 1_000 ether);
        vm.deal(challenger, 1_000 ether);
    }

    // ------------------------------------------------------------------ 动作面

    /// commit 顺序 epoch：nIntents 条随机意图（收款人池 3 选、金额 1-500）。
    function commitEpoch(uint256 nIntentsRaw, uint256 rSeed, uint256 aSeed) external {
        uint256 n = 1 + (nIntentsRaw % 4);
        uint256 epochId = epochCount;
        IntentFields[] memory intents = new IntentFields[](n);
        uint64[] memory seqs = new uint64[](n);
        for (uint256 i = 0; i < n; i++) {
            intents[i] = IntentFields({
                agent: bytes20(uint160(0x1111)),
                delegationHash: keccak256(abi.encodePacked(epochId, i)),
                recipient: bytes20(recipients[(rSeed >> (8 * i)) % 3]),
                amount: uint64(1 + (aSeed >> (8 * i)) % 500),
                category: bytes32(uint256(0x4444)),
                spendNonce: uint64(i + 1),
                memo: new bytes(0),
                expiresAt: type(uint64).max
            });
            seqs[i] = ++seqCounter;
            committed[epochId].push(IntentRec(intents[i], seqs[i]));
        }
        bytes32[] memory leaves = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            leaves[i] = leaf(seqs[i], intentHash(intents[i]));
        }
        bytes32 root = merkleRoot(leaves);

        vm.prank(operator);
        bs.commit{value: BOND}(epochId, root, keccak256("revocation"), ACCEPTANCE_ROOT, SEALED_AT);
        ghostBondSum += BOND;
        epochCount++;
    }

    /// settle：fraudMode % 4 → 0/3 诚实；1 漏掉一个收款人行（kind1 面）；2 砍半首行
    ///（kind2 面）。settle 恒按 Σnet 精确注资（资金守恒的前提——超额注资是未记账捐赠）。
    function settleEpoch(uint256 epochId, uint256 fraudMode) external {
        if (epochId >= epochCount || settledEpoch[epochId]) return;
        IntentRec[] storage list = committed[epochId];
        if (list.length == 0) return;

        // 诚实净额：按收款人聚合（3 收款人池，直接扫描）。
        BatchSettler.NetInstruction[] memory honest = new BatchSettler.NetInstruction[](0);
        for (uint256 r = 0; r < 3; r++) {
            uint256 sum = _committedSum(epochId, bytes20(recipients[r]));
            if (sum > 0) {
                BatchSettler.NetInstruction[] memory tmp =
                    new BatchSettler.NetInstruction[](honest.length + 1);
                for (uint256 i = 0; i < honest.length; i++) {
                    tmp[i] = honest[i];
                }
                tmp[honest.length] = BatchSettler.NetInstruction(recipients[r], sum);
                honest = tmp;
            }
        }
        require(honest.length > 0, "no net");

        BatchSettler.NetInstruction[] memory net = honest;
        uint256 mode = fraudMode % 4;
        if (mode == 1 && honest.length > 0) {
            // 漏单：删掉最后一行。
            net = new BatchSettler.NetInstruction[](honest.length - 1);
            for (uint256 i = 0; i < net.length; i++) {
                net[i] = honest[i];
            }
        } else if (mode == 2) {
            // 低付：首行砍半。
            net = new BatchSettler.NetInstruction[](honest.length);
            for (uint256 i = 0; i < honest.length; i++) {
                net[i] = honest[i];
            }
            net[0].amount = net[0].amount / 2;
        }

        uint256 total = _sum(net);
        vm.prank(operator);
        bs.settle{value: total}(epochId, net, keccak256(abi.encode(net)));
        settledEpoch[epochId] = true;
        settledAtOf[epochId] = block.timestamp;
        fundedOf[epochId] = total;
        for (uint256 i = 0; i < net.length; i++) {
            netLines[epochId].push(net[i]);
        }
        ghostFundedSum += total;
    }

    /// 窗口内真欺诈挑战：从已提交意图 × 净额行推可成立的证明（先 kind1 后 kind2）；
    /// 诚实净额（无候选）revert 由 fail_on_revert=false 吸收。
    function challengeFraud(uint256 epochId) external {
        if (epochId >= epochCount || !settledEpoch[epochId] || voidedEpoch[epochId]) return;
        if (block.timestamp > settledAtOf[epochId] + WINDOW) return;

        // kind1 候选：收款人不在 net[] 的已提交意图。
        IntentRec[] storage list = committed[epochId];
        for (uint256 i = 0; i < list.length; i++) {
            if (!_netHas(epochId, list[i].fields.recipient)) {
                _challenge(epochId, _kind1Proof(epochId, i));
                return;
            }
        }
        // kind2 候选：net 行金额 < 该收款人已提交总额。
        for (uint256 i = 0; i < netLines[epochId].length; i++) {
            BatchSettler.NetInstruction memory line = netLines[epochId][i];
            uint256 sum = _committedSum(epochId, bytes20(line.recipient));
            if (sum > line.amount) {
                _challenge(epochId, _kind2Proof(epochId, i, bytes20(line.recipient)));
                return;
            }
        }
        revert("no fraud candidate");
    }

    /// 窗口内垃圾挑战（空证明）→ 驳回 + 押金销毁，epoch 状态必须零改动（押金进出
    /// 相抵，不进 ghost）。
    function challengeGarbage(uint256 epochId) external {
        if (epochId >= epochCount || !settledEpoch[epochId] || voidedEpoch[epochId]) return;
        if (block.timestamp > settledAtOf[epochId] + WINDOW) return;
        BatchSettler.IntentProof[] memory none = new BatchSettler.IntentProof[](0);
        vm.prank(challenger);
        bs.challenge{value: DEPOSIT}(
            epochId, BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: none})
        );
    }

    /// warp 过挑战窗后 claim。
    function warpAndClaim(uint256 epochId, uint256 idx) external {
        if (epochId >= epochCount || !settledEpoch[epochId] || voidedEpoch[epochId]) return;
        if (idx >= netLines[epochId].length) return;
        uint256 target = settledAtOf[epochId] + WINDOW + 1;
        if (block.timestamp < target) {
            vm.warp(target);
        }
        BatchSettler.NetInstruction memory line = netLines[epochId][idx];
        vm.prank(challenger); // claim 无权限面，任意调用者
        bs.claim(epochId, idx);
        ghostClaimedSum += line.amount;
    }

    /// warp 过挑战窗后 release 债券（S-77 happy path 退回）：债券同时移出 storage 与
    /// 合约余额 → ghost 净扣。已 release / voided 的 epoch 不重入。
    function releaseBond(uint256 epochId) external {
        if (epochId >= epochCount || !settledEpoch[epochId] || voidedEpoch[epochId]) return;
        if (releasedEpoch[epochId]) return;
        uint256 target = settledAtOf[epochId] + WINDOW + 1;
        if (block.timestamp < target) {
            vm.warp(target);
        }
        vm.prank(operator);
        bs.releaseBond(epochId);
        releasedEpoch[epochId] = true;
        ghostBondSum -= BOND;
    }

    /// ③ 行为断言：voided 后 claim 必须拒绝（try/catch 而非 expectRevert，
    /// 避免被 fail_on_revert=false 吞掉）。
    function claimVoidedMustRevert(uint256 epochId) external {
        if (epochId >= epochCount || !voidedEpoch[epochId]) return;
        try bs.claim(epochId, 0) {
            brokenVoidedClaim = true;
        } catch {
            // 预期：EpochVoided
        }
    }

    /// 时间推进（< 窗口量级，制造窗口边缘压力但不系统性杀死挑战覆盖）。
    function advanceTime(uint256 secs) external {
        vm.warp(block.timestamp + 1 + (secs % 1 hours));
    }

    // ------------------------------------------------------------------ internals

    function _challenge(uint256 epochId, BatchSettler.FraudProof memory fp) internal {
        vm.prank(challenger);
        bs.challenge{value: DEPOSIT}(epochId, fp);
        // 挑战成功：bonded/settlementFunded 被清零 → ghost 按调用前原额扣减（storage 已
        // 清零不可再读；押金原额退回挑战者，不进 ghost）。
        (,,,,, uint256 bonded, uint256 funded,,) = bs.epochs(epochId);
        (,,, bool voided_) = bs.epochStatus(epochId);
        assertTrue(voided_, "valid fraud proof must void the epoch");
        assertEq(bonded + funded, 0, "success zeroes both accounts");
        ghostBondSum -= BOND;
        ghostFundedSum -= fundedOf[epochId];
        voidedEpoch[epochId] = true;
    }

    function _kind1Proof(uint256 epochId, uint256 i)
        internal
        view
        returns (BatchSettler.FraudProof memory)
    {
        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](1);
        ips[0] = toIntentProof(committed[epochId][i].fields, _bundle(epochId, i));
        return BatchSettler.FraudProof({kind: 1, targetNetIndex: 0, intents: ips});
    }

    function _kind2Proof(uint256 epochId, uint256 targetNetIndex, bytes20 recipient)
        internal
        view
        returns (BatchSettler.FraudProof memory)
    {
        IntentRec[] storage list = committed[epochId];
        uint256 n = 0;
        for (uint256 i = 0; i < list.length; i++) {
            if (list[i].fields.recipient == recipient) n++;
        }
        BatchSettler.IntentProof[] memory ips = new BatchSettler.IntentProof[](n);
        uint256 k = 0;
        for (uint256 i = 0; i < list.length; i++) {
            if (list[i].fields.recipient == recipient) {
                ips[k++] = toIntentProof(list[i].fields, _bundle(epochId, i));
            }
        }
        return BatchSettler.FraudProof({kind: 2, targetNetIndex: targetNetIndex, intents: ips});
    }

    function _bundle(uint256 epochId, uint256 i) internal view returns (ProofBundle memory) {
        IntentRec[] storage list = committed[epochId];
        uint256 n = list.length;
        bytes32[] memory leaves = new bytes32[](n);
        for (uint256 j = 0; j < n; j++) {
            leaves[j] = leaf(list[j].seq, intentHash(list[j].fields));
        }
        (uint256 accepted, bytes32[] memory siblings) = proofFor(leaves, i);
        return ProofBundle(list[i].seq, i, accepted, siblings);
    }

    function _committedSum(uint256 epochId, bytes20 recipient) internal view returns (uint256 s) {
        IntentRec[] storage list = committed[epochId];
        for (uint256 i = 0; i < list.length; i++) {
            if (list[i].fields.recipient == recipient) s += list[i].fields.amount;
        }
    }

    function _netHas(uint256 epochId, bytes20 recipient) internal view returns (bool) {
        for (uint256 i = 0; i < netLines[epochId].length; i++) {
            if (bytes20(netLines[epochId][i].recipient) == recipient) return true;
        }
        return false;
    }

    function _sum(BatchSettler.NetInstruction[] memory net) internal pure returns (uint256 s) {
        for (uint256 i = 0; i < net.length; i++) {
            s += net[i].amount;
        }
    }
}

contract BatchSettlerInvariantTest is Test {
    SettlerHandler internal handler;

    function setUp() public {
        handler = new SettlerHandler();
        targetContract(address(handler));
    }

    /// ① 资金守恒：余额 == Σbonded（净已释放）+ Σfunded - Σ已付 claim。
    function invariant_solvency() public view {
        assertEq(
            address(handler.bs()).balance,
            handler.ghostBondSum() + handler.ghostFundedSum() - handler.ghostClaimedSum(),
            "ETH balance must equal tracked funds minus paid claims"
        );
    }

    /// ② 状态机单调性（全部已创建 epoch 枚举）。
    function invariant_state_machine() public view {
        for (uint256 i = 0; i < handler.epochCount(); i++) {
            (bool committed_, bool settled_, bool challenged_, bool voided_) =
                handler.bs().epochStatus(i);
            assertTrue(!settled_ || committed_, "settled implies committed");
            assertTrue(!voided_ || challenged_, "voided implies challenged");
            assertTrue(!challenged_ || voided_, "challenged implies voided");
        }
    }

    /// ③ voided 后 claim 必须拒绝。
    function invariant_voided_claim_rejected() public view {
        assertFalse(handler.brokenVoidedClaim(), "claim succeeded on voided epoch");
    }
}
