// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./BytesUtils.sol";

/**
 * @notice modified from https://github.com/daimo-eth/p256-verifier/
 */
library P256Verifier {
    using BytesUtils for bytes;

    address internal constant NATIVE_P256_VERIFIER = 0x0000000000000000000000000000000000000100;
    address internal constant FALLBACK_P256_VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;

    function ecdsaVerify(bytes32 messageHash, bytes memory signature, bytes memory key)
        internal
        view
        returns (bool verified)
    {
        bytes memory args = abi.encode(
            messageHash,
            uint256(bytes32(signature.substring(0, 32))),
            uint256(bytes32(signature.substring(32, 32))),
            uint256(bytes32(key.substring(0, 32))),
            uint256(bytes32(key.substring(32, 32)))
        );

        (bool hasResult, bool nativeVerified) = _tryVerify(NATIVE_P256_VERIFIER, args);
        if (hasResult) {
            return nativeVerified;
        }

        (hasResult, verified) = _tryVerify(FALLBACK_P256_VERIFIER, args);
        assert(hasResult); // require either native precompile or fallback contract
    }

    function _tryVerify(address verifier, bytes memory args) private view returns (bool hasResult, bool verified) {
        (bool success, bytes memory ret) = verifier.staticcall(args);
        if (!success || ret.length != 32) {
            return (false, false);
        }

        hasResult = true;
        verified = abi.decode(ret, (uint256)) == 1;
    }
}
