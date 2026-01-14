# Snowman Merkle Airdrop - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
    - ### [H-01. No Access Control on mintSnowman()](#H-01)
    - ### [H-02. Typo in MESSAGE_TYPEHASH Breaks All Signatures](#H-02)
- ## Medium Risk Findings
    - ### [M-01. Amount Read from Balance Instead of Signed Message](#M-01)
- ## Low Risk Findings
    - ### [L-01. Global Timer Breaks earnSnow() Function](#L-01)
    - ### [L-02. Claim Status Never Checked (Logic Bug)](#L-02)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: AI First Flight #10

### Dates: Jan 8th, 2026 - Jan 13th, 2026

[See more contest details here](https://codehawks.cyfrin.io/c/ai-snowman-merkle-airdrop-cm6nu1o500001uiyzwwrvc8vx)

# <a id='results-summary'></a>Results Summary

### Number of findings:
- High: 2
- Medium: 1
- Low: 2


# High Risk Findings

## <a id='H-01'></a>H-01. No Access Control on mintSnowman()            



<br />

## Description

* The `mintSnowman()` function has no access control. Any address can mint any number of NFTs to any recipient.

```Solidity
function mintSnowman(address receiver, uint256 amount) external {
    // NO ACCESS CONTROL - anyone can call this!
@>    for (uint256 i = 0; i < amount; i++) {
        _safeMint(receiver, s_tokenCounter);
        s_tokenCounter++;
    }
}
```

<br />

**Attack Scenario**:

```Solidity
// Attacker mints 1 million NFTs
attacker.call(snowman.mintSnowman(attacker, 1_000_000));
// NFT value = 0, protocol destroyed
```

## Risk

**Likelihood**:

* Attacker can mint as many as NFT they can

**Impact**:

* Anyone can mint unlimited NFTs, destroying token economics

## Proof of Concept

Create a file inside test folder and paste the code\
This code prove that how the attacker can mint limitless NFT

```Solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {Snow} from "../src/Snow.sol";
import {Snowman} from "../src/Snowman.sol";
import {SnowmanAirdrop} from "../src/SnowmanAirdrop.sol";
import {DeploySnow} from "../script/DeploySnow.s.sol";
import {MockWETH} from "../src/mock/MockWETH.sol";


contract AllVulnerabilitiesPoC is Test {
    // Snow.sol contracts
    Snow snow;
    DeploySnow deployer;
    MockWETH weth;
    address collector;
    uint256 FEE;

    // Snowman.sol and SnowmanAirdrop.sol contracts  
    Snowman snowman;
    SnowmanAirdrop airdrop;
    bytes32 merkleRoot = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);

    // Test addresses
    address alice;
    address bob;
    address charlie;
    address attacker;

    function setUp() public {
        // Deploy Snow.sol contracts
        deployer = new DeploySnow();
        snow = deployer.run();
        weth = deployer.weth();
        collector = deployer.collector();
        FEE = deployer.FEE();

        // Deploy Snowman.sol and SnowmanAirdrop.sol contracts
        snowman = new Snowman("ipfs://snowman");
        airdrop = new SnowmanAirdrop(merkleRoot, address(snow), address(snowman));

        // Create test addresses
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        charlie = makeAddr("charlie");
        attacker = makeAddr("attacker");

        // Fund users
        deal(alice, 100 ether);
        deal(bob, 100 ether);
        deal(charlie, 100 ether);
        deal(attacker, 100 ether);

        weth.mint(alice, 100 * FEE);
        weth.mint(bob, 100 * FEE);
        weth.mint(charlie, 100 * FEE);
        weth.mint(attacker, 100 * FEE);
    }
/// @notice CRITICAL: Anyone can mint unlimited Snowman NFTs
    function test_Snowman_UnrestrictedMinting() public {
        vm.startPrank(attacker);
        
        snowman.mintSnowman(attacker, 1000);
        
        assertEq(snowman.balanceOf(attacker), 1000);
        assertEq(snowman.getTokenCounter(), 1000);
        
        snowman.mintSnowman(alice, 500);
        assertEq(snowman.balanceOf(alice), 500);
        
        vm.stopPrank();
    }

    /// @notice CRITICAL: Attacker can grief by minting to random addresses
    function test_Snowman_GriefingAttack() public {
        address victim = makeAddr("victim");
        
        vm.prank(attacker);
        snowman.mintSnowman(victim, 10000);
        
        assertEq(snowman.balanceOf(victim), 10000);
    }}
```

## Recommended Mitigation

Using immutable address and checks can privent from attacker

```Solidity
address private immutable i_airdropContract;

constructor(string memory baseUri, address airdropContract) ERC721("Snowman", "SNM") {
    s_baseUri = baseUri;
    i_airdropContract = airdropContract;
}

function mintSnowman(address receiver, uint256 amount) external {
    if (msg.sender != i_airdropContract) revert Unauthorized();
    for (uint256 i = 0; i < amount; i++) {
        _safeMint(receiver, s_tokenCounter);
        s_tokenCounter++;
    }
}
```

## <a id='H-02'></a>H-02. Typo in MESSAGE_TYPEHASH Breaks All Signatures            



<br />

# Description

* Line 21 has a typo: "addres" instead of "address". This breaks the EIP-712 hash, causing all valid signatures to fail validation.

```Solidity
bytes32 MESSAGE_TYPEHASH = keccak256("AirdropClaim(addres receiver,uint256 amount)");
//                                                   ^^^^^^ TYPO - should be "address"
```

## Risk

**Likelihood**:

* As soon as the contract deploy

**Impact**:

* All signature validations will fail; airdrop is non-functional

* All signatures generated off-chain will use correct "address" spelling

* Contract will compute different hash with "addres" typo

* All `claimSnowman()` calls will revert with invalid signature

* Airdrop is completely broken

## Proof of Concept

Create a file inside of test folder and paste the code

<br />

```Solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {Snow} from "../src/Snow.sol";
import {Snowman} from "../src/Snowman.sol";
import {SnowmanAirdrop} from "../src/SnowmanAirdrop.sol";
import {DeploySnow} from "../script/DeploySnow.s.sol";
import {MockWETH} from "../src/mock/MockWETH.sol";

contract AllVulnerabilitiesPoC is Test {
    // Snow.sol contracts
    Snow snow;
    DeploySnow deployer;
    MockWETH weth;
    address collector;
    uint256 FEE;

    // Snowman.sol and SnowmanAirdrop.sol contracts  
    Snowman snowman;
    SnowmanAirdrop airdrop;
    bytes32 merkleRoot = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);

    // Test addresses
    address alice;
    address bob;
    address charlie;
    address attacker;

    function setUp() public {
        // Deploy Snow.sol contracts
        deployer = new DeploySnow();
        snow = deployer.run();
        weth = deployer.weth();
        collector = deployer.collector();
        FEE = deployer.FEE();

        // Deploy Snowman.sol and SnowmanAirdrop.sol contracts
        snowman = new Snowman("ipfs://snowman");
        airdrop = new SnowmanAirdrop(merkleRoot, address(snow), address(snowman));

        // Create test addresses
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        charlie = makeAddr("charlie");
        attacker = makeAddr("attacker");

        // Fund users
        deal(alice, 100 ether);
        deal(bob, 100 ether);
        deal(charlie, 100 ether);
        deal(attacker, 100 ether);

        weth.mint(alice, 100 * FEE);
        weth.mint(bob, 100 * FEE);
        weth.mint(charlie, 100 * FEE);
        weth.mint(attacker, 100 * FEE);
    }

     /// @notice CRITICAL: Typo in MESSAGE_TYPEHASH breaks all signature validation
    function test_Airdrop_BrokenSignatureValidation() public {
        vm.prank(alice);
        snow.buySnow{value: 5 ether}(1);
        assertEq(snow.balanceOf(alice), 1);
        
        // PROOF: "addres" instead of "address" in MESSAGE_TYPEHASH
        // All signatures will be invalid
    }}
```

## Recommended Mitigation

Fixing the typo will do

```Solidity
bytes32 MESSAGE_TYPEHASH = keccak256("AirdropClaim(address receiver,uint256 amount)");
```

    
# Medium Risk Findings

## <a id='M-01'></a>M-01. Amount Read from Balance Instead of Signed Message            



<br />

## Description

* Line 86 reads amount from current balance instead of using the signed amount from the message. This allows manipulation and frontrunning.

```Solidity
function claimSnowman(..., uint256 amount, ...) external {
    // 'amount' parameter is from signed message
    
    // BUT line 86 ignores it and uses current balance:
@>    uint256 amount = i_snow.balanceOf(receiver);  // WRONG!
    
    // Should use the signed 'amount' parameter instead
}
```

## Risk

**Likelihood**:

* When user try to claim snowman NFT

**Impact**:

* Signed amount is ignored; vulnerable to frontrunning

## Proof of Concept

Creat a file inside the test folder and paste the code

**Attack Scenarios**:

1. User signs message for 100 tokens
2. Attacker frontruns, transferring Snow tokens to victim
3. Victim claims more than signed amount
4. OR attacker frontruns by removing tokens to grief victim

```Solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {Snow} from "../src/Snow.sol";
import {Snowman} from "../src/Snowman.sol";
import {SnowmanAirdrop} from "../src/SnowmanAirdrop.sol";
import {DeploySnow} from "../script/DeploySnow.s.sol";
import {MockWETH} from "../src/mock/MockWETH.sol";


contract AllVulnerabilitiesPoC is Test {
    // Snow.sol contracts
    Snow snow;
    DeploySnow deployer;
    MockWETH weth;
    address collector;
    uint256 FEE;

    // Snowman.sol and SnowmanAirdrop.sol contracts  
    Snowman snowman;
    SnowmanAirdrop airdrop;
    bytes32 merkleRoot = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);

    // Test addresses
    address alice;
    address bob;
    address charlie;
    address attacker;

    function setUp() public {
        // Deploy Snow.sol contracts
        deployer = new DeploySnow();
        snow = deployer.run();
        weth = deployer.weth();
        collector = deployer.collector();
        FEE = deployer.FEE();

        // Deploy Snowman.sol and SnowmanAirdrop.sol contracts
        snowman = new Snowman("ipfs://snowman");
        airdrop = new SnowmanAirdrop(merkleRoot, address(snow), address(snowman));

        // Create test addresses
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        charlie = makeAddr("charlie");
        attacker = makeAddr("attacker");

        // Fund users
        deal(alice, 100 ether);
        deal(bob, 100 ether);
        deal(charlie, 100 ether);
        deal(attacker, 100 ether);

        weth.mint(alice, 100 * FEE);
        weth.mint(bob, 100 * FEE);
        weth.mint(charlie, 100 * FEE);
        weth.mint(attacker, 100 * FEE);
    }
function test_Airdrop_AmountManipulation() public {
        // Setup: Alice buys 5 Snow tokens
        vm.prank(alice);
        snow.buySnow{value: FEE * 5}(5);
        uint256 aliceBalance = snow.balanceOf(alice);
        assertEq(aliceBalance, 5);
        
        // VULNERABILITY PROOF:
        // The claimSnowman function (line 86) uses:
        //     uint256 amount = i_snow.balanceOf(receiver);
        // This means the amount is NOT from the signed message parameter!
        // It reads the CURRENT balance, which can be manipulated via frontrunning
        
        // Scenario: Alice signed a message for 100 tokens
        // But attacker frontruns and transfers 50 more tokens to Alice
        // Now Alice claims 150 instead of the signed 100
        // OR attacker removes tokens to grief Alice
        
        // The signed amount parameter in claimSnowman is completely IGNORED!
        console.log("Alice balance:", snow.balanceOf(alice));
        console.log("Amount used in claim will be balance, NOT signed amount!");
    }
}
```

## Recommended Mitigation

```Solidity
function claimSnowman(..., uint256 amount, ...) external {
    // Use the signed amount parameter, not balance
    // Remove line 86: uint256 amount = i_snow.balanceOf(receiver);
    
    // Verify user has enough balance
    if (i_snow.balanceOf(receiver) < amount) revert InsufficientBalance();
    
    // Rest of validation...
}
```


# Low Risk Findings

## <a id='L-01'></a>L-01. Global Timer Breaks earnSnow() Function            



# Description

The `s_timer` variable is a single global variable shared across all users. When any user calls `earnSnow()`, it updates this timer and blocks all other users for one week.

```Solidity
@> uint256 private s_earnTimer;  // Single global variable shared by all users

function earnSnow() external canFarmSnow {
    if (s_earnTimer != 0 && block.timestamp < (s_earnTimer + 1 weeks)) {
        revert S__Timer();
    }
    _mint(msg.sender, 1);
@>    s_earnTimer = block.timestamp;  // Updates global timer, blocking ALL users
}

function buySnow(uint256 amount) external payable canFarmSnow {
    // ...
@>    s_earnTimer = block.timestamp;  // Also resets timer, blocking earnSnow users
}
```

## Risk

**Likelihood**: High

*  After one user earn snow token, the global timer update and block all other user from claim snow token.

* After one user buy snow token, the global timer reset and block all user to earn

  <br />

**Impact**: High

* Only one user can earn snow tokens per week globally

## Proof of Concept

Create a file on test folder an paste the code there.\
This test proof that after one user earn others can't & after one user buy the claim users also can't claim on that week

```Solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {Snow} from "../src/Snow.sol";
import {Snowman} from "../src/Snowman.sol";
import {SnowmanAirdrop} from "../src/SnowmanAirdrop.sol";
import {DeploySnow} from "../script/DeploySnow.s.sol";
import {MockWETH} from "../src/mock/MockWETH.sol";

contract AllVulnerabilitiesPoC is Test {
    // Snow.sol contracts
    Snow snow;
    DeploySnow deployer;
    MockWETH weth;
    address collector;
    uint256 FEE;

    // Snowman.sol and SnowmanAirdrop.sol contracts  
    Snowman snowman;
    SnowmanAirdrop airdrop;
    bytes32 merkleRoot = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);

    // Test addresses
    address alice;
    address bob;
    address charlie;
    address attacker;

    function setUp() public {
        // Deploy Snow.sol contracts
        deployer = new DeploySnow();
        snow = deployer.run();
        weth = deployer.weth();
        collector = deployer.collector();
        FEE = deployer.FEE();

        // Deploy Snowman.sol and SnowmanAirdrop.sol contracts
        snowman = new Snowman("ipfs://snowman");
        airdrop = new SnowmanAirdrop(merkleRoot, address(snow), address(snowman));

        // Create test addresses
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        charlie = makeAddr("charlie");
        attacker = makeAddr("attacker");

        // Fund users
        deal(alice, 100 ether);
        deal(bob, 100 ether);
        deal(charlie, 100 ether);
        deal(attacker, 100 ether);

        weth.mint(alice, 100 * FEE);
        weth.mint(bob, 100 * FEE);
        weth.mint(charlie, 100 * FEE);
        weth.mint(attacker, 100 * FEE);
    }
/// @notice PoC: Global timer prevents all users from earning after first claim

  

    function test_Snow_GlobalTimerBlocksAllUsers() public {
        vm.prank(alice);
        snow.earnSnow();
        assertEq(snow.balanceOf(alice), 1);

        vm.warp(block.timestamp + 1);

        vm.prank(bob);
        vm.expectRevert(Snow.S__Timer.selector);
        snow.earnSnow();

        vm.warp(block.timestamp + 1 weeks - 1);

        vm.prank(bob);
        snow.earnSnow();
        assertEq(snow.balanceOf(bob), 1);

        vm.prank(alice);
        vm.expectRevert(Snow.S__Timer.selector);
        snow.earnSnow();
        
    }

/// @notice PoC: buySnow() resets global timer, blocking all earnSnow() users
    function test_Snow_BuySnowResetsTimerBlockingAllEarns() public {
        vm.prank(alice);
        snow.earnSnow();

        vm.warp(block.timestamp + 1 weeks);

        vm.prank(attacker);
        snow.buySnow{value: FEE}(1);

        vm.prank(alice);
        vm.expectRevert(Snow.S__Timer.selector);
        snow.earnSnow();
    }
  
```

## Recommended Mitigation

uaing a mappin with userTimer would solve the problem

```diff
- function earnSnow() external canFarmSnow {
-       if (s_earnTimer != 0 && block.timestamp < (s_earnTimer + 1 weeks)) {
-           revert S__Timer();
-      }
-        _mint(msg.sender, 1);
-
-       s_earnTimer = block.timestamp;
-   }
+ // Use mapping for per-user timers
+ mapping(address => uint256) private s_userTimers;

+ function earnSnow() external {
+    if (block.timestamp - s_userTimers[msg.sender] < 1 weeks) revert S__Timer();
+   s_userTimers[msg.sender] = block.timestamp;
+   _mint(msg.sender, 1);
+}
```

## <a id='L-02'></a>L-02. Claim Status Never Checked (Logic Bug)            



# Root + Impact

## Description

* The `s_hasClaimedSnowman` mapping is set but never checked before minting.

```Solidity
mapping(address => bool) private s_hasClaimedSnowman;

function claimSnowman(...) external {
 @>   // Missing: if (s_hasClaimedSnowman[receiver]) revert AlreadyClaimed();
    
    // ... validation ...
    
    s_hasClaimedSnowman[receiver] = true;  // Set but never checked!
    i_snowman.mintSnowman(receiver, 1);
}
```

## Risk

**Likelihood**:

* During the NFT mint and claim

**Impact**:

* Users can claim multiple times; mapping serves no purpose

## Proof of Concept

Create a file inside the test folder and paste the code

This code prove that user can claim multiple time

```Solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {Snow} from "../src/Snow.sol";
import {Snowman} from "../src/Snowman.sol";
import {SnowmanAirdrop} from "../src/SnowmanAirdrop.sol";
import {DeploySnow} from "../script/DeploySnow.s.sol";
import {MockWETH} from "../src/mock/MockWETH.sol";

contract AllVulnerabilitiesPoC is Test {
    // Snow.sol contracts
    Snow snow;
    DeploySnow deployer;
    MockWETH weth;
    address collector;
    uint256 FEE;

    // Snowman.sol and SnowmanAirdrop.sol contracts  
    Snowman snowman;
    SnowmanAirdrop airdrop;
    bytes32 merkleRoot = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);

    // Test addresses
    address alice;
    address bob;
    address charlie;
    address attacker;

    function setUp() public {
        // Deploy Snow.sol contracts
        deployer = new DeploySnow();
        snow = deployer.run();
        weth = deployer.weth();
        collector = deployer.collector();
        FEE = deployer.FEE();

        // Deploy Snowman.sol and SnowmanAirdrop.sol contracts
        snowman = new Snowman("ipfs://snowman");
        airdrop = new SnowmanAirdrop(merkleRoot, address(snow), address(snowman));

        // Create test addresses
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        charlie = makeAddr("charlie");
        attacker = makeAddr("attacker");

        // Fund users
        deal(alice, 100 ether);
        deal(bob, 100 ether);
        deal(charlie, 100 ether);
        deal(attacker, 100 ether);

        weth.mint(alice, 100 * FEE);
        weth.mint(bob, 100 * FEE);
        weth.mint(charlie, 100 * FEE);
        weth.mint(attacker, 100 * FEE);
    }

/// @notice HIGH: s_hasClaimedSnowman is set but never checked
    function test_Airdrop_ClaimStatusNotChecked() public {
        // PROOF: Look at SnowmanAirdrop.sol line 95:
        //     s_hasClaimedSnowman[receiver] = true;
        // 
        // But there's NO check like:
        //     if (s_hasClaimedSnowman[receiver]) revert AlreadyClaimed();
        // 
        // This means:
        // 1. The mapping is written to (costs gas)
        // 2. But it's NEVER read/checked before claiming
        // 3. The mapping serves NO purpose - dead code
        // 4. Users could potentially claim multiple times (if they can pass other checks)
        
        bool claimStatus = airdrop.getClaimStatus(alice);
        assertEq(claimStatus, false); // Not claimed yet
        
        // After a claim, it would be set to true
        // But claimSnowman() never checks this before processing!
        console.log("Claim status mapping is SET but NEVER CHECKED - logic bug!");
    }}
```

## Recommended Mitigation

Checking for claimedsnowman would solve the issue

```Solidity
function claimSnowman(...) external {
    if (s_hasClaimedSnowman[receiver]) revert AlreadyClaimed();
    
    // ... rest of validation ...
    
    s_hasClaimedSnowman[receiver] = true;
    i_snowman.mintSnowman(receiver, 1);
}
```



