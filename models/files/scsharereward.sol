pragma experimental ABIEncoderV2;
pragma solidity ^0.5.0;

contract ShareReward{
    // rewardName: reward name
    // addr: reward address
    // amount: reward amount
    // deposit: deposit amount
    event RewardDetail(string rewardName, address addr, uint256 amount, uint256 deposit);

    // chargeRatio: pool node service charge ratio
    // settleRoot: settle root
    // poolAddress: pool reward address
    function shareReward(string memory chargeRatio, bytes memory settleRoot, bytes memory poolAddress) public payable returns(bool status){}


}
