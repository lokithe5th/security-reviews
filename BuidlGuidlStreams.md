# BuidlGuidl Security Review  

The review covers the BuidlGuidl streaming contract found [here](https://github.com/BuidlGuidl/hacker-houses-streams/blob/token-streams/packages/hardhat/contracts/YourContract.sol)

[Commit reviewed](https://github.com/BuidlGuidl/hacker-houses-streams/commit/2011448e30de5f17650273bab311f222b685a4a1)  

## Introduction  
The contract is meant to stream ETH and ERC20 tokens to members of the BuidlGuidl that have a valid stream.  

## Severity Classification  

The review uses three levels of severity classfication using the [Code4rena classification guidlines](https://docs.code4rena.com/awarding/judging-criteria/severity-categorization).  

| Severity | Description |
| --- | --- | 
| High | Assets can be stolen/lost/compromised directly (or indirectly if there is a valid attack path that does not have hand-wavy hypotheticals) |
| Medium | Assets not at direct risk, but the function of the protocol or its availability could be impacted, or leak value with a hypothetical attack path with stated assumptions, but external requirements. |
| QA | Includes both Non-critical (code style, clarity, syntax, versioning, off-chain monitoring (events, etc)) and Low risk (e.g. assets are not at risk: state handling, function incorrect as to spec, issues with comments). Excludes Gas optimizations, which are submitted and judged separately | 
| Gas | Comments related to gas usage and optimization |  

___

## Disclosures and Comments  
The security reviewer is a member of BuidlGuidl and receives streamed ETH from the guild. The review is done as a practice review by the security researcher, with no expectation of remuneration.  

Although a thorough security review is crucial, it is important to note that no security review can completely eliminate smart contract risk. It is always advisable to have a strong security posture with regular monitoring and review of security threats.  

## Summary  

The security reviewer used manual review for the one contract in scope.  

The following issues were found:  

| Issue | Severity | Description |
| --- | --- | --- |
| M-1 | Medium | Floating pragma|
| M-2 | Medium | Unsafe use of `transfer`|
| QA-1 | QA/LOW | `BuilderStreamInfo` can be more efficiently arranged | 
| QA-2 | QA/LOW | BuilderData can be more efficiently arranged |
| QA-3 | QA/LOW | Loading structs into memory |
| QA-4 | QA/LOW | Contract funds cannot be recovered |
| QA-5 | QA/LOW | Missing equality check for array lengths |
| GAS-1 | GAS | For loops |
| GAS-2 | GAS | USe `if/then` instead of `require` |

### M-1: Floating Pragma  

As a general rule it is always advisable to use a specific pragma version for compilation. 

Although normally not an issue that is classified as medium severity, the recent inclusion of the `PUSH0` opcode in the `0.8.20` compiler is a good example of issues arising with floating pragmas. In this case, if the contract would need to be deployed on a L2 chain, then the compiled contract (if the deployer's `solc` version is set to `0.8.20`, which is possible due to pragma `>=0.8.0 <0.9.0`) might not function as expected. 

Read more about `PUSH0` and it's benefits [here](https://medium.com/coinmonks/push0-opcode-a-significant-update-in-the-latest-solidity-version-0-8-20-ea028668028a)  

**Recommendation:** Use compiler version `0.8.19`. Alternatively, add a comment to the contract highlighting this risk to deployers.  

### M-2: Unchecked return value of `transfer` calls for ERC20 tokens  

The `IERC20.transfer(address to, uint256 amount)` function call in the `streamWithdraw` function does not check the result of the token transfer call. This could lead to scenarios where the token `transfer` returns `false` indicating transfer failure, but, as the value is not checked, the transaction continues and the builders withdrawal is still credited. See [here](https://solodit.xyz/issues/m-01-unchecked-transfers-code4rena-boot-finance-boot-finance-contest-git) for an example.   

**Recommendation:** Use the `safeTransfer` functions from the OpenZeppelin `SafeERC20` library.  

### QA-1: `BuilderStreamInfo` can be more efficiently arranged  

**Issue:** The time-related state variable `FREQUENCY` and `BuilderStreamInfo.last` use the type `uint256`. This is more than needed for time-related variables. Although only a QA issue, this configuration affords some room for optimization and reduction of deployment costs.  

The maximum value for uint96 is: `79,228,162,514,264,337,593,543,950,335`, which equates to a unix timestamp thousands of years in the future.  

In storing `BuilderStreamInfo` structs the current configuration requires 3 storage slots: `cap`, `last`, and `optionalTokenAddress` all use one slot each.  

**Recommendation:** Modify the existing code in the following ways.  
`BuilderStreamInfo::last` should be of the type `uint96`

This configuration will allow the `BuilderStreamInfo` structs to be packed more efficiently, using only 2 slots of memory.

### QA-2: `BuilderData` can be more efficiently arranged  

In storing `BuilderData` structs the current configuration requires the use of 3 storage slots: `builderAddress` takes up 160 bits of the first slot, but 96 bits are left empty. The `cap` and `unlockedAmount` fields require full 32 byte slots for the respective uint256 values. 

**Recommendation**: Modify the existing code in the following ways.

`BuilderData::cap` can be a `uint128`
`BuilderData::unlockedAmount` can also be a `uint128`  

These changes should result in more efficient storage use. More importantly, `uint128` still equates to `340,282,366,920,938,463,463,374,607,431,768,211,455`, which is more than adequate for streams.  

### QA-3: Loading structs into `memory`  

In the functions `unlockedBuilderAmount` and `updateBuilderStreamCap` the target `_builder`'s stream info struct is loaded into `memory`. Loading into memory is expensive. It may also create confusion to newer developers as values are copied into memory first, but then accessed directly via the default storage pointers thereafter.

**Recommendation:** There is no need to load the stream info into `memory` for this function. The `BuilderStreamInfo[_builder].cap` value can be read and set using the default/implicit (or an explicit) storage pointer. 

In other words, rather use: 

```
        require(streamedBuilders[_builder].cap > 0, "No active stream for builder");
        streamedBuilders[_builder].cap = _cap;
```

### QA-4: Contract funds cannot be recovered  

Not an issue, but it is good practice to implement a way for the deployer/owner to recover any tokens/ETH which may become stuck in the contract.  

### QA-5: Missing equality check for array lengths  

In `addBatch` [here](https://github.com/BuidlGuidl/hacker-houses-streams/blob/2011448e30de5f17650273bab311f222b685a4a1/packages/hardhat/contracts/YourContract.sol#L60) there is a check for the length of two of the supplied arrays, but the `optionalTokenAddress` array's length is never checked. This leaves the function vulnerable to out of bounds reverts.  

**Recommendation:** This appears to be a minor oversight. Implementing an additional `&&` condition in the `require` statement fixes this.


### GAS-1: For Loops  

**Recommendation:** To save on gas cache the length the array to traverse outside the loop and increment in an unchecked block at the end of the loop. 

Also, inside the loop there is no need to initialize values to `0`. 

### GAS-2: Use `if/then` with `revert error` instead of `require`  

**Recommendation:** Using an `if/then` pattern which reverts with a custom error uses less gas than a `require` statement with strings.