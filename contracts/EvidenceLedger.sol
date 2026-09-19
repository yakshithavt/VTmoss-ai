// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title EvidenceLedger
/// @notice Anchors a cryptographic fingerprint of an investigation -- NOT the
///         raw evidence itself -- so anyone can later verify whether a given
///         report/evidence set still matches what was registered.
/// @dev This contract does not, and cannot, assert that the underlying AI
///      conclusion is factually correct. It only proves that a specific
///      (merkleRoot, reportHash) pair was registered under a given caseId at
///      a given time by a given address.
contract EvidenceLedger {
    struct CaseRecord {
        bytes32 merkleRoot;
        bytes32 reportHash;
        uint256 timestamp;
        address registeredBy;
        bool exists;
    }

    mapping(string => CaseRecord) private cases;

    event CaseRegistered(
        string indexed caseId,
        bytes32 merkleRoot,
        bytes32 reportHash,
        uint256 timestamp,
        address indexed registeredBy
    );

    error CaseAlreadyRegistered(string caseId);
    error CaseNotFound(string caseId);
    error EmptyCaseId();

    /// @notice Registers the cryptographic fingerprint of a finalized case.
    /// @dev A case can only be registered once -- re-anchoring a modified
    ///      report requires a new caseId (e.g. "VK-2026-0017-v2"), which
    ///      preserves the original registration as an immutable audit trail
    ///      instead of silently overwriting it.
    function registerCase(string calldata caseId, bytes32 merkleRoot, bytes32 reportHash) external {
        if (bytes(caseId).length == 0) revert EmptyCaseId();
        if (cases[caseId].exists) revert CaseAlreadyRegistered(caseId);

        cases[caseId] = CaseRecord({
            merkleRoot: merkleRoot,
            reportHash: reportHash,
            timestamp: block.timestamp,
            registeredBy: msg.sender,
            exists: true
        });

        emit CaseRegistered(caseId, merkleRoot, reportHash, block.timestamp, msg.sender);
    }

    /// @notice Reads back a registered case record.
    function getCase(string calldata caseId) external view returns (
        bytes32 merkleRoot,
        bytes32 reportHash,
        uint256 timestamp,
        address registeredBy
    ) {
        CaseRecord memory rec = cases[caseId];
        if (!rec.exists) revert CaseNotFound(caseId);
        return (rec.merkleRoot, rec.reportHash, rec.timestamp, rec.registeredBy);
    }

    /// @notice Convenience view: does a case exist on-chain at all?
    function caseExists(string calldata caseId) external view returns (bool) {
        return cases[caseId].exists;
    }

    /// @notice Recomputes verification off the currently-supplied values
    ///         against the on-chain record, in one call.
    function verifyCase(string calldata caseId, bytes32 currentMerkleRoot, bytes32 currentReportHash)
        external
        view
        returns (bool verified)
    {
        CaseRecord memory rec = cases[caseId];
        if (!rec.exists) revert CaseNotFound(caseId);
        return rec.merkleRoot == currentMerkleRoot && rec.reportHash == currentReportHash;
    }
}
