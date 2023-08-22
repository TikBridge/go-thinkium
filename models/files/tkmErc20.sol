pragma solidity ^0.5.9;

contract tkmBridgeERC20 {
    // function in interface ERC20
    function transfer(address _to, uint256 _value) public returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) external returns (bool success);

    // mint _value token for _to
    function sysBridgeMint(address _to, uint256 _value) external;

    // brun _value token in _to, _to should had approved to sysbridge
    function sysBridgeBurn(address _to, uint256 _value) external;
}