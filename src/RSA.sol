// SPDX-License-Identifier: MIT
/// @author : mrWojackETH
pragma solidity ^0.8.19;


contract RSA {
    /// @notice generate public and private key
    // Choose {p,q} prime numbers
    // Choose {e} so that is also prime and is betweeen 0 and n=p*q
    // The function generates {d} with the parameters
    function keyGen(
        uint256 p,
        uint256 q,
        uint256 e
    ) external pure returns (bytes memory prKey, bytes memory pubKey) {
        require(_isPrime(p), "p!=prime");
        require(_isPrime(q), "q!=prime");
        require(_isPrime(e), "e!=prime");
        require(p >= 1 && q >= 1, "param<1");
        // calculate phi(p,q) with Euler Totient function
        uint256 phi = _phi(p, q);
        uint256 n = p * q;
        require((e > 1 && e < phi) && phi % n != 0, "e>1||e<phi||n mult e");
        uint256 d = _getD(phi, e);
        // d is the inverse of e
        require((d * e) % phi == 1, "incorrect d");
        //encode keys into a bytes to make it easier to manage(it can be decoded at any time)
        prKey = abi.encode(d, n); // private key contains {d}(secret) and {n}(exposed in public key)
        pubKey = abi.encode(e, n); // public key contains {e,n} and both are exposed
    }

    /// @notice Euler Totient function
    /// it calculates the amount of numbers that are smaller than {n = p* q} that have no common factor
    function _phi(uint256 p, uint256 q) private pure returns (uint256) {
        /// can be easily calculated if {p} and {q} are given
        return (p - 1) * (q - 1);
    }

    /// @notice compute the inverse to meet requirement : d * e % phi == 1, using Euler Totient algorithm
    function _getD(uint256 c0, uint256 c1) private pure returns (uint256 d) {
        int256[] memory c = new int256[](c1);
        int256[] memory b = new int256[](c1);
        bool found = false;
        c[0] = int256(c0);
        c[1] = int256(c1);
        b[0] = 0;
        b[1] = 1;
        int256 t;
        uint256 i = 1;
        while (!found) {
            c[i + 1] = c[i - 1] % c[i];
            t = c[i - 1] / c[i];
            b[i + 1] = b[i - 1] - (t * b[i]);
            if (c[i + 1] == 1) {
                found = true;
                break;
            }
            i++;
        }
        d = b[i + 1] >= 0 ? uint256(b[i + 1]) : uint256(b[i + 1] + int256(c1));
    }

    function sign(
        uint256 m,
        bytes memory prKey
    ) external pure returns (bytes memory mProof) {
        (uint256 d, uint256 n) = abi.decode(prKey, (uint256, uint256));
        uint256 rawMProof = _binExp(m, d, n);
        mProof = abi.encode(rawMProof);
    }

    /*  function sign(
        bytes memory c,
        bytes memory prKey
    ) external pure returns (bytes memory cProof) {
        uint256 rawC = abi.decode(c, (uint));
        (uint256 d, uint256 n) = abi.decode(prKey, (uint256, uint256));
        uint256 rawCProof = _binExp(m, d, n);
        cProof = abi.encode(rawCProof);
    } */

    function verify(
        bytes memory proof,
        bytes memory pubKey
    ) external pure returns (uint256 m) {
        (uint256 e, uint256 n) = abi.decode(pubKey, (uint256, uint256));
        m = _binExp(abi.decode(proof, (uint256)), e, n);
    }

    /// @notice encrypt message with receiver's public key
    /// @notice use binary exponentiation to handle huge numbers
    function encrypt(
        uint256 m,
        bytes memory pubKey
    ) external pure returns (bytes memory c) {
        // decode public key to get {e,n}
        (uint256 e, uint256 n) = abi.decode(pubKey, (uint256, uint256));
        // cepherText = message ** e % n
        uint256 rawC = _binExp(m, e, n);
        // encode cepherText
        c = abi.encode(rawC);
    }

    /// @notice computate x**pow % mod usind binary exponentiation
    function _binExp(
        uint256 _x,
        uint256 _pow,
        uint256 _mod
    ) private pure returns (uint256) {
        uint256 res = 1;
        _x = _x % _mod;
        if (_x == 0) return 0;

        while (_pow > 0) {
            if (_pow % 2 == 1) res = (res * _x) % _mod;
            _pow = _pow >> 1;
            _x = (_x * _x) % _mod;
        }
        return res;
    }

    /// @notice decrypt message with own private key
    function decrypt(
        bytes memory c,
        bytes memory prKey
    ) external pure returns (uint256 m) {
        (uint256 d, uint256 n) = abi.decode(prKey, (uint256, uint256));
        uint256 rawC = abi.decode(c, (uint256));
        m = _binExp(rawC, d, n);
    }

    /// @notice square root function
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

    /// @notice check if a number is prime
    function _isPrime(uint256 _n) private pure returns (bool) {
        if (_n <= 1) return false;
        for (uint256 i = 2; i < _sqrt(_n) + 1; i++) {
            if (_n % i == 0) return false;
        }
        return true;
    }
}
