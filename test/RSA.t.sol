// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "forge-std/Test.sol";
import "../src/RSA.sol";

contract RSATest is Test {
    address public constant user1 = address(0x1);
    address public constant user2 = address(0x2);
    RSA public rsa;

    function setUp() public {
        rsa = new RSA();
    }

    // we preselect {p,q,e} because its computationally expensive to generate big random prime numbers that meet the requirements
    function testKeyGen()
        public
        returns (bytes memory prKey, bytes memory pubKey)
    {
        // generate private and public key
        (prKey, pubKey) = rsa.keyGen(571, 619, 211);
        //decode them
        (uint256 d, uint256 n1) = abi.decode(prKey, (uint256, uint256));
        (uint256 e, uint256 n2) = abi.decode(pubKey, (uint256, uint256));
        // assert prKey(d,n) is (156931, 353449)
        assertEq(d, 156931);
        assertEq(n1, 353449);
        // assert pubKey(e,n) is (211, 353449)
        assertEq(e, 211);
        assertEq(n2, 353449);
        console.log("d :", d, " n : ", n1);
        console.log("e :", e, " n : ", n2);
    }

    function testSendMessages(uint256 m) public {
        //the message "m" will be a random uint so that {1 < m < 10000000}
        vm.assume(m > 1 && m < 100000);
        //user 1 generates keys
        vm.startPrank(user1);
        (bytes memory pr1, bytes memory pub1) = rsa.keyGen(571, 619, 211);
        vm.stopPrank();
        //user 2 gnerates keys
        vm.startPrank(user2);
        (bytes memory pr2, bytes memory pub2) = rsa.keyGen(2287, 2371, 2357);
        vm.stopPrank();
        //user1 encrypts message for user 2
        vm.startPrank(user1);
        bytes memory cepherText = rsa.encrypt(m, pub2); //uses user 2's public key
        vm.stopPrank();
        //decrypt is as user2 using own private key
        vm.startPrank(user2);
        uint256 m_ = rsa.decrypt(cepherText, pr2);
        console.log("DECRYPTED : ", m_);
        vm.stopPrank();
        //make sure the decrypted message equals the original message "m"
        assertEq(m_, m, "m!=m");
        // if we decrypt it with any other private key we get a wrong message
        uint256 wrongMessage = rsa.decrypt(cepherText, pr1);
        console.log("wrong : ", wrongMessage);
        assertFalse(wrongMessage == m);
    }
/* 
    // sign a message with a private key and verify that person signed the message with his public key
    function testSignTransparentMesssage(uint256 m) public {
        vm.assume(m > 1 && m < 1000000);
        rsa.keyGen(43261, 43313, 43291);
        (bytes memory prKey, bytes memory pubKey) = rsa.keyGen(571, 619, 211);
        bytes memory proof = rsa.sign(m, prKey);
        uint256 verified = rsa.verify(proof, pubKey);
        assertEq(m, verified);
    }
 */
    function _isPrime(uint256 n) private pure returns (bool) {
        if (n <= 1) return false;
        for (uint256 i = 2; i < _sqrt(n) + 1; i++) {
            if (n % i == 0) return false;
        }
        return true;
    }

    function _sqrt(uint256 _y) private pure returns (uint z) {
        if (_y > 3) {
            z = _y;
            uint x = _y / 2 + 1;
            while (x < z) {
                z = x;
                x = (_y / x + x) / 2;
            }
        } else if (_y != 0) {
            z = 1;
        }
    }
}
