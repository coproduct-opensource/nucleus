// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Minimal ERC-8004 Validation Registry (self-deploy for Base Sepolia)
/// @notice The canonical ERC-8004 ValidationRegistry is NOT published on Base
/// Sepolia (84532) and the spec is still in flux, so we deploy a minimal,
/// selector-compatible implementation of the v1.x Validation interface. The
/// Identity (0x8004A818…BD9e) and Reputation (0x8004B663…8713) registries ARE
/// canonical on Base Sepolia and are used as-is.
///
/// Selectors match the v1.x spec:
///   validationRequest(address,uint256,string,bytes32)  -> 0xaaf400c4
///   validationResponse(bytes32,uint8,string,bytes32,string) -> 0x3d659a96
///   getValidationStatus(bytes32) -> 0xff2febfc
///
/// Anchoring model: the requester commits a request keyed by `requestHash`
/// (keccak256 of the off-chain receipt/bundle pointed to by `requestURI`); only
/// the named validator may post the `validationResponse` (a bounded 0–100 score
/// + a tag, e.g. "clearing/in-bounds"). Third parties verify entirely from
/// on-chain reads.
contract ValidationRegistry {
    struct Validation {
        address validator;
        uint256 agentId;
        uint8 response;
        bool requested;
        bool responded;
    }

    mapping(bytes32 => Validation) private _validations;

    event ValidationRequest(
        address indexed validatorAddress,
        uint256 indexed agentId,
        string requestURI,
        bytes32 indexed requestHash
    );

    event ValidationResponse(
        address indexed validatorAddress,
        uint256 indexed agentId,
        bytes32 indexed requestHash,
        uint8 response,
        string responseURI,
        bytes32 responseHash,
        string tag
    );

    error AlreadyRequested();
    error UnknownRequest();
    error NotValidator();
    error ResponseOutOfRange();

    /// Commit a validation request: bind `requestHash` to the chosen validator +
    /// agent, pointing at the off-chain payload via `requestURI`.
    function validationRequest(
        address validatorAddress,
        uint256 agentId,
        string calldata requestURI,
        bytes32 requestHash
    ) external {
        if (_validations[requestHash].requested) revert AlreadyRequested();
        _validations[requestHash] = Validation({
            validator: validatorAddress,
            agentId: agentId,
            response: 0,
            requested: true,
            responded: false
        });
        emit ValidationRequest(validatorAddress, agentId, requestURI, requestHash);
    }

    /// Post the validator's verdict for a prior request. Only the named
    /// validator may call this; `response` is a bounded 0–100 score.
    function validationResponse(
        bytes32 requestHash,
        uint8 response,
        string calldata responseURI,
        bytes32 responseHash,
        string calldata tag
    ) external {
        Validation storage v = _validations[requestHash];
        if (!v.requested) revert UnknownRequest();
        if (msg.sender != v.validator) revert NotValidator();
        if (response > 100) revert ResponseOutOfRange();
        v.response = response;
        v.responded = true;
        emit ValidationResponse(
            msg.sender,
            v.agentId,
            requestHash,
            response,
            responseURI,
            responseHash,
            tag
        );
    }

    /// The bounded 0–100 score for a responded request. Reverts if no response.
    function getValidationStatus(bytes32 requestHash) external view returns (uint8) {
        Validation storage v = _validations[requestHash];
        if (!v.responded) revert UnknownRequest();
        return v.response;
    }

    /// Whether a request has a posted response (non-reverting probe).
    function isValidated(bytes32 requestHash) external view returns (bool) {
        return _validations[requestHash].responded;
    }
}
