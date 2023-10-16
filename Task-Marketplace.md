## Security Review for Task Marketplace

## Details  

The security review took place over a period of 2 days. The reviewer used the following methods:

1. Manual code review
2. Foundry with custom test cases

### Date  
Initial review: 18-19 September 2023
Revision 1: 29 September 2023* 

>*Please note: the findings for Revision 1 are appended to the end of this document.

### Repo Details  
The files in scope are the following:  
`PayoutUponCompletions.sol`

The commit hash used for this review was:
[f8e819976e142ab8bdc02cee17b2cc9dd42be235](https://github.com/escottalexander/taskmarketplace/commit/f8e819976e142ab8bdc02cee17b2cc9dd42be235)  

### Security Reviewer  
The review was carried out by Lourens Linde.

## Severity Classification  
The findings of this security review are classified according to the impact and the likelihood of occurrence.  

Impact is defined as below.

| Impact | Description |
| --- | --- | 
| High | Assets can be stolen/lost/compromised directly (or indirectly if there is a valid attack path that does not have hand-wavy hypotheticals) |
| Medium | Assets not at direct risk, but the function of the protocol or its availability could be impacted, or leak value with a hypothetical attack path with stated assumptions, but external requirements. |  
| Low | No assets at risk, but contracts not working as expected (e.g. assets are not at risk: state handling, function incorrect as to spec, issues with comments) |  
| QA | Non-critical issues (code style, clarity, syntax, versioning, off-chain monitoring (events, etc)) | 
| Gas | Comments related to gas usage and optimization |  

Severity is given by taking the likelihood and the impact into account. See the below table.

| Severity               | Impact: High | Impact: Medium | Impact: Low |
| ---------------------- | ------------ | -------------- | ----------- |
| **Likelihood: High**   | Critical     | High           | Medium      |
| **Likelihood: Medium** | High         | Medium         | Low         |
| **Likelihood: Low**    | Medium       | Low            | Low         |

## Disclosures and Comments  
The security reviewer is a member of BuidlGuidl and receives streamed ETH from the guild. The review is done as a practice review by the security researcher.

Although a thorough security review is crucial, it is important to note that no security review can completely eliminate smart contract risk. It is always advisable to have a strong security posture with regular monitoring and review of security threats.

## Overview  
Token Marketplace is a project that hopes to allow users to complete tasks for remuneration while allowing tasks to be funded in a decentralized manner.

## Findings

The issues found in the in-scope files are contained in the following sections. 

### Summary of Findings  

The following issues were found:  

| Issue | Severity | Description |
| --- | --- | --- |
| C-01.1 | Critical | Tasks cannot be cancelled by *anyone* until the unlock period has passed|
| C-01.2 | Critical | Only the reviewer can cancel tasks|
| C-02 | Critical | `cancelTask` can be used to steal funds from the protocol | 
| H-01 | High | An approved worker has no guarantee that they will be paid |
| M-01 | Medium | Unbounded array growth can make a task expensive to finalize or cancel |
| M-02 | Medium | The internal accounting will fail with rebase and fee-on-transfer ERC20 tokens |
| L-01 | Low | The `createTask` function does not return the `id` of the new task |
| L-02 | Low | `receive()` and `fallback()` can be removed  |
| L-03 | Low | Packing the `Task` struct  |
| QA-01 | QA/Gas | Remove unnecessary `IERC20.sol` import |
| QA-02 | QA/Gas | Use `constant` instead of `immutable` |
| QA-03 | QA/Gas | Move the input validation for `createTask` and `createAndFundTask` into `_createTask` |
| QA-04 | QA/Gas | Use `unchecked` math where safe |
| QA-05 | QA/Gas | Work can be submitted for non-existant or completed tasks |
| QA-06 | QA/Gas | `_divideWithBasisPoints()` does not improve precision in `_divyUp()`  |


### Revision 1

In addition, the following was noted after the review fixes were implemented: 

| Issue | Severity | Description |
| --- | --- | --- |
| M-03 | Medium | `cancelTask` receives an array of address arrays which must be iterated through |
| L-04 | Low | `getTaskFunding()` may revert |
| L-05 | Low |  3-level nested mapping increases chances of storage collisions  |

---
<br/> 

### C-01.1: Tasks cannot be cancelled by *anyone* until the unlock period has passed  

#### Impact  
>This issue, `C01.1` and `C01.2` share the same root cause, but the impacts are slightly different. For all intents and purposes this is one issue, but both are included here for completeness.  

There is a check in the `cancelTask` function which [reads](https://github.com/escottalexander/taskmarketplace/blob/f8e819976e142ab8bdc02cee17b2cc9dd42be235/packages/hardhat/contracts/PayoutUponCompletion.sol#L258):  
```
if (msg.sender != task.reviewer || block.timestamp - unlockPeriod < task.creationTime) {
	revert NotAuthorized();
}
```

This means that if either `msg.sender != task.reviewer` **OR** `block.timestamp - unlockPeriod < task.creationTime` is `TRUE`, then the function will be reverted with `NotAuthorized()`. Calls to this function can only succeed if the unlock period has passed **AND** the caller is the `task.reviewer`. 

This is high impact, as it locks funds in the task until the timelock has passed. It is also high likelihood, as it will affect every call to `cancelTask()`.

#### PoC
The below is the code from the Foundry test to prove this PoC.  

This can be run using the provided test repo with the following command:
`forge test --match-test testCancelTaskReviewerBeforeUnlock`

```
    function testCancelTaskReviewerBeforeUnlock(string memory location, address reviewer) public {
        vm.assume(reviewer != address(0) && reviewer != address(payout));
        uint256 taskIndex = payout.currentTaskIndex();
        skip(payout.unlockPeriod());
        testCreateTask(location, reviewer, 10);
        vm.startPrank(reviewer);
        vm.expectRevert(PayoutUponCompletion.NotAuthorized.selector);
        payout.cancelTask(taskIndex);
    }
```

#### Recommended Mitigation  
Modify the `if` statement in `cancelTask` [here](https://github.com/escottalexander/taskmarketplace/blob/f8e819976e142ab8bdc02cee17b2cc9dd42be235/packages/hardhat/contracts/PayoutUponCompletion.sol#L258-L260), so that it checks the conditions as stated in the natspec.

#### Comments  

*Confirmed*  

The developer has reworked the `cancelTask` function and applied the requisite checks to ensure that the function can only be called at the appropriate time. 

```
        if (
            msg.sender != task.reviewer &&
            block.timestamp < task.creationTime + unlockPeriod
        ) {
            revert NotAuthorized();
        }
```

---
### C-01.2: Only the reviewer can cancel tasks  

#### Impact  

> This issue, `C01.2` and `C01.1` share the same root cause, but the impacts are slightly different. For all intents and purposes this is one issue, but both are included here for completeness.  

The natspec for `cancelTask` states: `Only the reviewer can cancel unless the unlock period has passed, then anyone can cancel.`

But due to this [statement](https://github.com/escottalexander/taskmarketplace/blob/f8e819976e142ab8bdc02cee17b2cc9dd42be235/packages/hardhat/contracts/PayoutUponCompletion.sol#L258-L260): `if (msg.sender != task.reviewer ||...`, the call will always revert if the `msg.sender` is not the `task.reviewer`.  

The result is that tasks cannot be cancelled by non-reviewer users after the unlock period has passed.

The impact of this high and the likelihood is high in scenarios where `cancelTask` is needed. It will affect all calls to the `cancelTask` made after the unlock period has passed and lock the funds permanently if the reviewer is unable to execute their role (due to death or loss of keys).

#### PoC  
The below test proves that the other users are unable to cancel the task even after the `unlockPeriod` has passed.

This can be run using the provided test repo with the following command:
`forge test --match-test testCancelTaskNotReviewer`

```
    function testCancelTaskNotReviewer(string memory location, address reviewer) public {
        vm.assume(reviewer != address(0) && reviewer != address(this));
        uint256 taskIndex = payout.currentTaskIndex();
        
        testCreateTask(location, reviewer, 10);
        skip(payout.unlockPeriod());
        vm.expectRevert(PayoutUponCompletion.NotAuthorized.selector);
        payout.cancelTask(taskIndex);
    }
```

#### Recommended Mitigation  
Modify the `if` statement in `cancelTask` [here](https://github.com/escottalexander/taskmarketplace/blob/f8e819976e142ab8bdc02cee17b2cc9dd42be235/packages/hardhat/contracts/PayoutUponCompletion.sol#L258-L260):
```
		if (msg.sender != task.reviewer && block.timestamp < task.creationTime + unlockPeriod) {
			revert NotAuthorized();
		}
```

#### Comment  

*Confirmed*  

The code has been reworked to anyone to cancel a task once the `unlockPeriod` has passed.  

```
        if (
            msg.sender != task.reviewer &&
            block.timestamp < task.creationTime + unlockPeriod
        ) {
            revert NotAuthorized();
        }
```

---
### C-02: `cancelTask` can be used to steal funds from the protocol  

#### Impact  
*Note: this vulnerability assumes that the check in `C-01.1` and `C-01.2` works as intended by the natspec, and not as it is currently implemented*

The `cancelTask` [function](https://github.com/escottalexander/taskmarketplace/blob/d86bb6c532de0fd6d914c6e6617a687925bd2fa7/packages/hardhat/contracts/PayoutUponCompletion.sol#L256-L281) intends to expose a method to allow the cancellation of tasks by either the reviewer or by any user after the `unlockPeriod` has passed.

Calling this function divides the funds allocated to that task among the current funders. The root cause is that the function call does not check a task's current status. This allows either the reviewer, or any user after the unlock period has passed, to call `cancelTask` multiple times, as long as the task hasn't been finalized yet. 

By calling the function multiple times an attacker is able inflate the `withdrawableFunds` and withdraw more funds than was allocated to that task. This allows an attacker to effectively steal the funds allocated to other tasks.

#### PoC  

The vulnerability lies in this [line](https://github.com/escottalexander/taskmarketplace/blob/d86bb6c532de0fd6d914c6e6617a687925bd2fa7/packages/hardhat/contracts/PayoutUponCompletion.sol#L271): 

```
		for (uint i; i < funderLength;) {
			for (uint h; h < fundingLength;) {
				address funder = task.funderAddresses[i];
				address token = task.fundingType[h];
				uint amount = task.funding[funder][token];
				if (amount > 0) {
					withdrawableFunds[funder][token] += amount;
				}
				unchecked {
					h ++;
				}
			}
			unchecked {
				i ++;
			}
		}
```

As there is no check in the function to ensure the task isn't already canceled, the attacker is able to call `cancelTask` multiple times, each time adding the `amount` they initially funded the task with to their `withdrawableFunds`. This can be done multiple times until the `withdrawableFunds` for the attacker becomes greater than what the task was funded with. At that point the attacker becomes able to withdraw assets intended for other tasks, leading to protocol wide losses. 

This can be done for *any task*, regardless if it has been finalized or not.

The below PoC confirms the attacker is able to inflate their `withdrawableFunds` using this method. 

This can be run using the provided test repo with the following command:
`forge test --match-test testCancelTaskMultipleCalls`

```
    function testCancelTaskMultipleCalls(string memory location, address reviewer) public {
        vm.assume(reviewer != address(0) && reviewer != address(this));
        uint256 taskIndex = payout.currentTaskIndex();
        
        testCreateTask(location, reviewer, 10);
        deal(address(10), 10 ether);
        vm.startPrank(address(10));
        payout.fundTask{value: 10 ether}(taskIndex, 10 ether, address(0));
        vm.stopPrank();

        skip(payout.unlockPeriod());

        vm.prank(reviewer);
        payout.cancelTask(taskIndex);

        vm.prank(address(10));
        uint256 withdrawableBalanceAfterFirstCancel = payout.getWithdrawableBalance(address(0));


        vm.prank(reviewer);
        payout.cancelTask(taskIndex);

        vm.prank(address(10));
        uint256 withdrawableBalanceAfterSecondCancel = payout.getWithdrawableBalance(address(0));

        assert(withdrawableBalanceAfterFirstCancel < withdrawableBalanceAfterSecondCancel);
    }
```

#### Recommended Mitigation  
Implement checks for a task's state before being able to set it to cancel.

#### Comment  

*Confirmed*  

A check was added to `cancelTask` to close this vulnerability. It involves checking that the target `taskIndex` has not already been cancelled.

```
        if (task.complete || task.canceled) {
            revert TaskInFinalState();
        }
```

---

### H-01: An approved worker has no guarantee that they will be paid  

#### Impact  

An `approvedWorker` for a task can be replaced at any time, even after the work has been received and the task has been finalized by the reviewer.

#### PoC  

Predatory practices in web2 labour marketplaces are a notable problem. A job poster (in this system the account that creates and funds a task) posts a task with a large pot. The job poster specifies the reviewer, which could just be an alternate account. The large reward attracts top workers, who complete the task. The worker submits this completed task. 

The reviewer (also the job poster), before calling finalize task swaps out the `approvedWorker` for their own address. 

```
	function setApprovedWorker(uint taskIndex, address approvedWorker) external {
		Task storage task = tasks[taskIndex];
		if (msg.sender != task.reviewer) {
			revert NotAuthorized();
		}
		task.approvedWorker = approvedWorker;

		emit ApprovedWorkerSet(taskIndex, approvedWorker);
	}
```

The worker has not been paid, but the task is completed; the worker has no recourse, and there is no repurcussion for the job poster.

#### Recommended Mitigation  

The `reviewer` cannot be regarded as a trusted role, as the job poster has an incentive to appoint a reviewer hostile to the worker. The `reviewer` should be independent (and ideally be a set of reviewers).

*Business logic suggestion*: it may be worthwhile exploring a way to create a pool of trusted reviewers which is managed by the protocol in a decentralized way (a suitable use case for a small DAO). A review might then take the form of two or more reviewers confirming a task's completion. This minimizes the risk of a funder abusing the system in this way.

#### Comment 

*Acknowledged*  

The developer acknowledges this risk and noted the following:  

> I came to the same conclusion that you pointed out, there is really nothing to keep a reviewer from acting maliciously. The one thing that I feel will act as a deterrent is that every action is recorded onchain so there is a clear record of what happened and when. A reputation system could be built off of that. Also, there is nothing to keep the reviewer address from representing a DAO that specializes in reviewing or a different multisig setup. This should be encouraged. 

No changes to the business logic implementation will be done in this instance and the developer plans to highlight this risk to users and encourage use of independent entities or DAO-like structures as reviewers. 

---
### M-01: Unbounded array growth can make a task expensive to finalize or cancel

#### Impact  
The `finalizeTask()` function allows a user to mark a task as completed. The `cancelTask()` function allows a task to be canceled once certain prerequisites are met. Both of these tasks use nested `for-loops`, which will iterate through the `fundingLength` and `funderAddresses` to allocate funds.

The issue is that these arrays get longer for every unique funder and unique token used. A task which is funded by many people and with many different assets will run the risk of running out of gas. The task can be pushed into this state through two mechanisms:  
1. Organic growth through funding popular tasks, from various addresses and with various tokens
2. An attacker creating junk tokens and populating tasks which have high asset values  

The effect is the same: a task becomes much more gas intensive to finalize or cancel.

The impact of this is high, but the likelihood is low, as there is no profit motive for the attacker. It has thus been classified as medium.

#### PoC
Using the below code, 
```
    function testGasGriefingPoC() public {
        address reviewer = address(0x110);
        uint256 amount = 1e18;
        testCreateTask("testing", reviewer, 10);

        ERC20[] memory tokens = new ERC20[](10000);

        for (uint256 i; i < 10000;) {
            tokens[i] = new ERC20("Junk", "JNK");
            deal(address(tokens[i]), address(this), amount);
            tokens[i].approve(address(payout), amount);
            payout.fundTask(0, amount, address(tokens[i]));

            unchecked {
                ++i;
            }
        }

        vm.startPrank(reviewer);
        payout.approveTask(0, address(111));
        payout.finalizeTask(0);
    }
```

... and running the gas-report. We can get the cost of calling `finalize` up to `0.7 ether`.  

#### Recommended Mitigation  
Nested `for-loops` in Solidity code are extremely gas intensive. Coupling that with unbounded arrays leaves the project vulnerable to gas-related griefing attacks.  

Although this is relatively less severe than the previous issues, this is likely to require significant refactoring. 

The recommendation would be: 
1. Refactor the code to remove the nested `for-loops`
2. Implement a whitelist of acceptable tokens and only accept funding in that token, this will prevent the `fundingTypes` array from growing too large

#### Comment  

*Confirmed*  

The code was refactored to remove the nested `for-loops`.  

A whitelist for acceptable tokens was implemented.

---
### M-02: The internal accounting will fail with rebase and fee-on-transfer ERC20 tokens  

#### Impact 
The contract allows any valid `ERC20` token to be used for funding tasks. 

The contract already uses `SafeERC20` for token interactions, which is helpful for preventing many token-related issues. However, this does not prevent issues arising from fee-on-transfer and rebase tokens.

As the contract holds an internal state of all token balances, it will experience a failure of internal accounting when used with such tokens.

#### PoC  
The below code shows where fee-on-transfer and rebase tokens will impact the internal accounting of the contract: 
```
		// Transfer value
		if (token == address(0)) {
			// Must be ETH
			if (amount == 0 || msg.value != amount) {
				revert AmountNotSet();
			}
		} else {
			if (amount == 0) {
				revert AmountNotSet();
			}
			IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
		}
		// Update State
		_addFunderAndFunds(task, amount, token);
```

The funder will specify an `amount`, but the actual `amount` received will be `amount - fees`, while the accounting will be for the full `amount`. 

#### Recommended Mitigation  
Consider adding a whitelist of acceptable tokens and stating that fee-on-transfer and rebase tokens are not supported. The effect will be two-fold:

1. The project is protected from incompatible tokens
2. The task workers are protected from fake ERC20 tokens impersonating well-known token.

#### Comment  

*Confirmed*  

The developer has implemented a whitelist pattern and will not support fee-on-transfer tokens.

---
### L-01: The `createTask` function does not return the `id` of the new task  

`_createTask` returns the index in the return variable `idx`, but this is not used in the `createTask` function.  

Consider adding this as a return value to assist other protocols with integrating with the project. Although the users may be able to glean the `taskId` from events emitted on the front-end, contracts on chain will not be able to.  

#### Comment  

*Fixed*  

The `createTask` function now returns the tasks index.

---
### L-02: `receive()` and `fallback()` can be removed  

The abovementioned function provide contracts the ability to receive ether directly (without a function call). 

The side-effect of having an empty `fallback()` function is that a call to the contract without a valid function signature will always succeed (although nothing is expected to happen in this contract). The side-effect of the explicit `receive()` function is that the contract can receive ether without adding it to it's tracked balances. This will require a call to `withdrawStuckTokens()` to clear again.   

Consider removing these two functions. The contract can still receive ether through the `createAndFundTask()` and `fundTask()` functions. 

#### Comment  

*Fixed*  

The `receive()` and `fallback()` functions were removed.

---
### L-03: Packing the `Task` struct  

The `Task` struct is not storage-layout optimized: 

```
	struct Task {
		address reviewer; // The one who can determine if this task has been completed, able to set to approved or canceled status
		uint8 reviewerPercentage; // Percentage of funds that go to reviewer, set at creation, payed out when worker claims funds
		address approvedWorker; // The worker who is able to claim funds when approved, can be set before or after work is submitted
		// mapping(address => uint) totalFunding; // TokenAddress => amount deposited - zero address for ETH - can be derived from funding below
		mapping(address => bool) hasFundingType; // Used for making sure fundingType only contains unique items
		address[] fundingType; // Token addresses for each asset funding
		mapping(address => bool) hasFunderAddress; // Used for making sure funderAddresses only contains unique items
		address[] funderAddresses; // Unique funder addresses
		mapping(address => mapping(address => uint)) funding; // FunderAddress => tokenAddress => amount
		uint creationTime; // Include this to refund users after certain time has passed
		bool approved; // Has task been reviewed and accepted, worker can be payed out
		bool canceled; // Everyone is refunded when a task moves to this state
		bool complete; // All funds have been allocated
	}
```

This struct could be packed so that storage variables fit into 32-byte slots. 

In addition, consider using an `Enum` to represent the `Task` status, this will use only a single 8-bit, instead of three, 8-bit slots for `bool` values.  

For a technical solution, consider packing `approved`, `canceled`, `complete` and `reviewerPercentage` into a `uint96` variable which can be stored after the 160-bit slot used by `reviewer`, this means all the aforementioned variables will fit into one 32-byte slot.

Consider removing `funderAddresses` and `fundingType` from the structs and placing them in the global storage. This will save storage space and costs.  

#### Comment  

*Fixed*  

The `Task` struct was reworked to pack variables more efficiently.

---
### QA-01: Remove unnecessary `IERC20.sol` import  

The `IERC20` interface is imported in the `SafeERC20` library as well. You can access it by specifying it in the import statement: 

```
import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
```

This will lead to a slight saving on deployment costs.  

#### Comment  

*Fixed*  

`IERC20.sol` is now only imported once.

---
### QA-02: Use `constant` instead of `immutable`  

Variables declared `immutable` should be set in the constructor. Variables where the values are known pre-deployment should be defined as `constant`.

This can be found [here](https://github.com/escottalexander/taskmarketplace/blob/d86bb6c532de0fd6d914c6e6617a687925bd2fa7/packages/hardhat/contracts/PayoutUponCompletion.sol#L34-L36).  

#### Comment  

*Fixed*  

The variables are now declared constant. 

*Please note that these variable names should be in capital letters*

---
### QA-03: Move the input validation for `createTask` and `createAndFundTask` into `_createTask`  

The identical input validation checks for the aforementioned functions are repeated in each function. Since these two functions share a common helper function consider moving the checks,

```
		if (reviewer == address(0)) {
			revert ZeroAddressNotAllowed();
		}
		if (reviewerPercentage > oneHundred) {
			revert ExceedsLimit();
		}
```
into the `_createTask` helper function. 

#### Comment   

*Fixed*  

The developer has moved these validation checks into `_createTask`.

---
### QA-04: Use `unchecked` math where safe

Where a value has been validated to be greater than anotherm using `unchecked` math will result in gas savings.  

This can be done [here](https://github.com/escottalexander/taskmarketplace/blob/d86bb6c532de0fd6d914c6e6617a687925bd2fa7/packages/hardhat/contracts/PayoutUponCompletion.sol#L149), but only with the calculation related to `withdrawableFunds`.

#### Comment  

*Fixed*  

Use of `unchecked` has been implemented as suggested.

---
### QA-05: Work can be submitted for non-existant or completed tasks  

The function [`submitWork()`](https://github.com/escottalexander/taskmarketplace/blob/d86bb6c532de0fd6d914c6e6617a687925bd2fa7/packages/hardhat/contracts/PayoutUponCompletion.sol#L248-L249) allows users to submit work for tasks that do not exist or have been completed and canceled.  

As this is the only way reviewers are notified that work has been done it may be worth adding input validation here.  

#### Comment  

*Fixed*  

Input validation has been added to the `submitWork` function.

---
### QA-06: `_divideWithBasisPoints()` does not improve precision in `_divyUp()` 

The natspec for the [function](https://github.com/escottalexander/taskmarketplace/blob/d86bb6c532de0fd6d914c6e6617a687925bd2fa7/packages/hardhat/contracts/PayoutUponCompletion.sol#L325-L332) states the intention of the funciton is to improve precision during calculations. But the implementation does not improve precision:  

```
		return (amount * tenThousand) / (divisor * tenThousand);
```

This is equivalent to adding `1e5` to the `amount` and the `divisor` at the same time, effectively canceling each other out without impacting the calculation. 

The idea of using basis points is a good one, as the dev states it is great for allowing granular control of a percentage variable. 

The recommendation would be to work with basis points directly in all logic where there is a percentage interaction. Also, clarify where inputs should be in 1/1000ths (`protocolTakerate`) or in 1/100ths (`reviewerPercentage`).

#### Comment  

*Fixed*  

The developer has reworked `_divideWithBasisPoints` into `_divideWithExtraPrecision`.

---  
---
## Revision 1  

The below issues are new findings based on the review of the fixes implemented.  

### Overview  

The contracts have been refactored substantially. The changes relate to the issues identified in the first security review. 

There are multiple, good quality comments present throughout the codebase. 

Testing coverage of the codebase has improved significantly.

In terms of general security posture the contract has been modified to use `Ownable2Step` which is good practice for any owned contract. 

### Additional Findings

The below are findings that were introduced with changes made in response to the initial review.

--- 

### M-03: `cancelTask` receives an array of address arrays which must be iterated through

#### Impact  
Allowing a dynamically sized array of dynamically sized arrays may lead to an out-of-gas error. In addition, it is ambigous in terms of input required.

This can lead to confusion when another protocol or user attempts to integrate this function.

The medium impact severity is noted because if a task is funded by many funders, iterating through that array may become too gas-intensive, making the canceling of a task impossible. This effect can be purposefully achieved by a griefer. 

It is not a high severity, as there is no profit motive and because the trusted reviewer may in that case set a friendly account as the `approvedWorker` and in this way "rescue" the funds. But this assumes that the `reviewer` is a trusted entity and will redistribute the funds.

#### Recommendation  

Rework the input for `cancelTask` to accept two arrays, `userArray` and `tokenArray` which map to `user => token`. Consider using an indexed loop to solve the gas griefing issue.  

#### Comments 
**Confirmed** 

The developer reworked the `cancelTask` function to accept two arrays as recommended. 


---
### L-04: `getTaskFunding()` may revert  

`getTaskFunding` includes a check:
```
		if (verificationTally != taskTally[taskIndex]) {
			revert InvalidAmount();
		}
```

This will revert the call to `getTaskFunding()` if there is a small difference in uint256 amounts. 

#### Recommendation  

As this is an external view function consider if the revert is desired here. This check is done with cancel task as well, and may not be appropriate in this view function.

#### Comments  

**Confirmed**

The developer modified `getTaskFunding` and removed the strict equality check. This was replaced with a `bool` flag to indicate if all the tokens were accounted for.

---


### L-05: 3-level nested mapping increases chances of storage collisions   

#### Impact  
The `taskFunding` mapping is a 3-level mapping used to keep track of each task, who has funded it, the token used and the amount funded with.  

The logic behind the implementation is clear, but there is a hidden danger: in a mapping there is a maximum number of 2^256 of storage locations. For each level a mapping is nested the amount of possible permutations increases by an order of magnitude.

#### PoC  

In a single mapping:
```
mapping(uint256 => address) exampleMap;
```

We have 2^256 possible entries. This is the maximum number of storage locations afforded by the EVM. If we create a nested mapping, like so:

```
mapping(uint256 => mapping(address => uint256)) exampleMap;
```

We now have 2^256 * 2^160 permutations. As the amount of levels increase so too does the number of permutations.   

The possible permutations in a nested mapping easily becomes larger than the amount of storage locations. But the risk of collision in such a large possibility space is very low, as 2^256 is in itself so large as to be practically unapproachable for most projects.

#### Recommendations  

For practical purposes it should not be an issue in this protocol. The team could consider splitting `taskFunding` into separate mappings. 

Another interesting alternative would be to pack the `tokenAddress` and the `amountFunded` into one `uint256` value. This will allow a two-level mapping and still support amounts up to 79 billion in value (assuming that the token has 18 decimals).    

#### Comments  

This is unlikely to impact the functioning of the protocol at this time.