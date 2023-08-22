pragma solidity ^0.5.9;

contract tkmBridgeERC721 {
    // function in interface ERC721
    function safeTransferFrom(address _from, address _to, uint256 _tokenId, bytes calldata _data) external payable;

    // mint _tokenId for _to, used to transfer the specified tokenId
    function sysBridgeClaim(uint256 _tokenId, address _to) external;

    // burn _tokenId, this token should be owned by the caller of sysbridge.burnERC721 and approved to sysbridge
    function sysBridgeBurn(uint256 _tokenId) external;
}