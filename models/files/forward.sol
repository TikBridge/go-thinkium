pragma solidity ^0.5.0;

contract Forwarder{

    // principal: raw transaction inputs
    function forward(bytes memory principal) public returns (bytes memory outOfPrincipal);
}
