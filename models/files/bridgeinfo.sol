pragma experimental ABIEncoderV2;
pragma solidity ^0.5.9;

contract BridgeInfo {
    struct ercInfo {
        uint256 chain;
        address addr;
    }

    // create mapping info about main erc contract to mapping contract
    // ercType: 0: ERC20, 1: ERC721, 2: ERC1155
    function createMap(ercInfo calldata from, ercInfo calldata to, uint8 ercType) external;

    // remove mapping info which mapping contract is on mappingChain and its address is mappingErc
    function removeMap(ercInfo calldata to) external;

    // list all mapping contracts of the main erc
    function listMappingsOf(ercInfo calldata main) external view returns (bool exist, ercInfo[] memory maps);

    // get the mapping info which mapping to "to"
    function getMappingInfoTo(ercInfo calldata to) external view returns (bool exist, ercInfo memory from, uint8 ercType);
}