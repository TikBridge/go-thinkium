pragma experimental ABIEncoderV2;
pragma solidity ^0.5.0;

contract POS{
    event MergedTo(bytes32 targetTxHash);

    // nodeId: binding NodeID
    // nodeType: should be 0 for Consensus, 1 for data
    // bindAddr: binding reward address which must equals to sender
    // nonce: equals nonce of the transaction
    // amount: amount of required reserve
    // nodeSig: hex string of signature(nodePk, Hash(join(nodeId, ',', nodeType, ',', bindAddr, ',', nonce, ',', amount))), for authrization and preventing replay attack
    function deposit(bytes memory nodeId, uint8 nodeType, address bindAddr, uint64 nonce, uint256 amount, string memory nodeSig) public payable returns(bool status);

    // nodeId: unbinding NodeID
    // bindAddr: unbinding reward address which must equals to sender
    function withdraw(bytes memory nodeId, address bindAddr) public returns(bool status, string memory errMsg);

    // nodeId: unbinding NodeID
    // bindAddr: unbinding reward address which must equals to sender
    // amount: amount of current withdrawing
    function withdrawPart(bytes memory nodeId, address bindAddr, uint256 amount) public returns(bool status, string memory errMsg);

    // nodeId: NodeID
    // era: era number of current era or next era
    // rootHashAtEra: the root hash of current or next required reserve trie
    function proof(bytes memory nodeId, uint64 era, bytes32 rootHashAtEra) public returns(bool exist, bytes memory proofs);

    struct posInfo {
        bytes nidHash;
        uint64 height;
        uint8 nodeType;
        uint256 depositing;
        uint256 validAmount;
        uint256 available;
        address rewardAddr;
        uint16 version;
        uint32 nodeCount;
        uint16 status;
        uint256 delegated;
        uint256 validDelegated;
    }

    function getInfo(bytes memory nodeId) public returns(bool exist, posInfo memory info);

    // bindAddr: binding reward address which must equals to sender
    function getDepositAmount(address bindAddr) public view returns(int amount);

    function getOngoingAmount(bytes memory nodeId) public view returns(int depositing, int withdrawing, bool exist);

    function setStatus(bytes memory nodeId, int16 statusValue) public returns(bool ok, string memory errMsg);
    function clrStatus(bytes memory nodeId, int16 statusValue) public returns(bool ok, string memory errMsg);

    // Delegate to node
    function delegate(bytes memory nodeId, uint256 amount) public payable returns(bool status);
    function undelegate(bytes memory nodeId, uint256 amount) public returns(bool status);

    // Penalize
    // PenaltyType: (penalRateNum/penalRateDenom | penalValue), if penalRateNum==0, penalValue must be >0
    function addPenaltyType(uint16 typeCode, uint256 penalRateNum, uint256 penalRateDenom, uint256 penalValue) public;
    function modifyPenaltyType(uint16 typeCode, uint256 penalRateNum, uint256 penalRateDenom, uint256 penalValue) public;
    function deletePenaltyType(uint16 typeCode) public;
    function getPenaltyType(uint16 typeCode) public returns(bool exist, uint256 penalRateNum, uint256 penalRateDenom, uint256 penalValue);
    function penalize(bytes memory nodeId, uint16 typeCode, uint32 chainId, uint64 rewardEra) public;
    event PendingPenalty(bytes32 indexed nodeIdHash, uint16 typeCode, uint256 estimated, uint32 chainId, uint64 rewardEra);
}
