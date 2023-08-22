pragma solidity ^0.5.0;

contract PoSv3{
    // nodeId: binding NodeID
    // nodeType: 0 for Consensus, 1 for DataNodes
    // chainId + epoch: where consensus occurred
    // era: era where reward request confirmed
    // should: blocks should be proposed
    // actual: blocks the node proposed actually
    // implicit parameter of auditedCount==0
    function report(bytes memory nodeId, uint8 nodeType, uint32 chainId, uint64 epoch, uint64 era, uint16 should, uint16 actual) public;

    // nodeId: binding NodeID
    // nodeType: 0 for Consensus, 1 for DataNodes
    // chainId + epoch: where consensus occurred
    // era: era where reward request confirmed
    // should: blocks should be proposed
    // actual: blocks the node proposed actually
    // auditedCount: since gtkm v3.2.1, returns the number of current node audited blocks when chainId.IsMain()==true
    function reportWithAudit(bytes memory nodeId, uint8 nodeType, uint32 chainId, uint64 epoch, uint64 era, uint16 should, uint16 actual, uint64 auditedCount) public;

    // rewardType: 0 for consensus, 1 for data, 2 for delegation, 3 for audited
    // era: reward era
    function award(uint8 rewardType, uint64 era) public payable;

    // transfer withdrawn value
    // NidHash: hash of NodeID
    function withdrawnDeposit(bytes memory NidHash) public payable;

    // transfer revoked delegation value
    // NidHash: hash of NodeID
    function delegationRevoked(bytes memory NidHash) public payable;
}
