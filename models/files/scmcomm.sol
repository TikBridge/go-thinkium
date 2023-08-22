pragma experimental ABIEncoderV2;
pragma solidity ^0.5.0;

contract ManageCommittee{
    // nodeIds: bytes of concatenated NodeIDs
    // returns the number of nodes added
    function addNodes(bytes[] memory nodeIds) public returns(bool status, uint8 delta, string memory errMsg){}

    // nodeIds: bytes of concatenated NodeIDs
    // returns the number of nodes deleted
    function delNodes(bytes[] memory nodeIds) public returns(bool status, uint8 delta, string memory errMsg){}

    // returns bytes of concatenated all NodeIDs
    function listNodes() public returns(bytes[] memory nodeIds){}
}