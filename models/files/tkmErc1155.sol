pragma solidity ^0.5.9;

contract tkmBridgeERC1155 {
    // function in interface ERC1155
    function safeTransferFrom(address _from, address _to, uint256 _id, uint256 _value, bytes calldata _data) external;

    // mint _value of _id for _to with extra _data
    function sysBridgeMint(address _to, uint256 _id, uint256 _value, bytes calldata _data) external;

    // burn _value of _id in _to
    function sysBridgeBurn(address _to, uint256 _id, uint256 _value) external;
}