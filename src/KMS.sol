// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import "src/OnchainRegistry.sol";

struct OnboardRequest {
	bytes pubkey;
	int nonce;
	address operator;
	bytes attestation;
}

contract KMS is AccessControl, Ownable, ReentrancyGuard, WorkloadGovernance, OnchainDiscovery {
    // Define roles as bytes32 constants
    bytes32 public constant ROLE_OPERATOR = keccak256("ROLE_OPERATOR");

    // Maximum size for byte arrays to prevent DoS attacks
    uint256 public constant MAX_BYTES_SIZE = 20 * 1024; // 20KB limit

	mapping(bytes32 => OnboardRequest) public onboardRequests;

    // State variables
    string[] public m_instanceDomainNames;
	AppPKI public app_pki;

	// Notes config and secrets locations
	string[] public storageBackends;
    // Maps config hash to config data and secrets for onchain DA
    mapping(bytes32 => bytes) public artifacts;
    // Maps identity to config hash
    mapping(bytes32 => bool) public allowlistedIdentities;

    // Events
    event InstanceDomainRegistered(string domain, address registrar);
	event StorageBackendSet(string location, address setter);
	event StorageBackendRemoved(string location, address remover);
    event ArtifactAdded(bytes32 configHash, address adder);
    event PKIUpdated(address updater, AppPKI pki);
    event IdentityAllowlisted(bytes32 identity, address setter);

    /**
     * @dev Constructor to set up initial roles.
     */
    constructor() Ownable(msg.sender) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ROLE_OPERATOR, msg.sender);
    }

    /**
     * @dev Modifier to check if input bytes size is within limits
     */
    modifier limitBytesSize(bytes memory data) {
        require(data.length <= MAX_BYTES_SIZE, "Data size exceeds limit");
        _;
    }

    /**
     * @dev Set PKI and its attestation
     * @param pki The PKI (certificate authority, encryption pubkey, kms attestation)
     */
    function setPKI(AppPKI memory pki)
        public 
        onlyOwner 
        limitBytesSize(pki.ca)
        limitBytesSize(pki.pubkey)
        limitBytesSize(pki.attestation)
    {
		app_pki = pki;
        emit PKIUpdated(msg.sender, pki);
    }

    function PKI() external view returns (AppPKI memory) {
		return app_pki;
	}

    /**
     * @dev Calculate DCAP identity from a report
     * @param report The DCAP report
     * @return identity The calculated identity hash
     */
    function DCAPIdentity(DCAPReport memory report, DCAPEvent[] memory /* eventLog */)
        public 
        view 
        returns (bytes32 identity) 
    {
        require(report.mrTd.length == 48, "incorrect mrtd length");
        require(report.RTMRs[0].length == 48, "incorrect RTMR[0] length");
        require(report.RTMRs[1].length == 48, "incorrect RTMR[1] length");
        require(report.RTMRs[2].length == 48, "incorrect RTMR[2] length");
        require(report.RTMRs[3].length == 48, "incorrect RTMR[3] length");
        require(report.mrOwner.length == 48, "incorrect mrOwner length");
        require(report.mrConfigId.length == 48, "incorrect mrConfigId length");
        require(report.mrConfigOwner.length == 48, "incorrect mrConfigOwner length");
        return keccak256(abi.encodePacked(address(this), report.RTMRs[0], report.RTMRs[1], report.RTMRs[2]));
    }

    /**
     * @dev Calculate MAA identity from a report
     * @param report The MAA report
     * @return identity The calculated identity hash
     */
    function MAAIdentity(MAAReport memory report) 
        public 
        view 
        returns (bytes32 identity) 
    {
        return keccak256(abi.encodePacked(address(this), report.PCRs[4], report.PCRs[9], report.PCRs[11]));
    }

	// Allowlisted identities
	function IdentityAllowed(bytes32 identity, address operator) external view returns (bool) {
		require(hasRole(ROLE_OPERATOR, operator), "Operator not authorized");
		return allowlistedIdentities[identity] == true;
	}

    /**
     * @dev Allowlist DCAP report
     * @param report The DCAP report
     */
    function allowlistDCAP(DCAPReport memory report) 
        public 
        onlyOwner 
		returns (bytes32 identity)
    {
		DCAPEvent[] memory emptyLog;
        identity = DCAPIdentity(report, emptyLog);
		allowlistIdentity(identity);
		return identity;
    }

    /**
     * @dev Allowlist MAA report
     * @param report The MAA report
     */
    function allowlistMAA(MAAReport memory report) 
        public 
        onlyOwner 
		returns (bytes32 identity)
    {
        identity = MAAIdentity(report);
		allowlistIdentity(identity);
		return identity;
    }

	function allowlistIdentity(bytes32 identity)
        public 
        onlyOwner 
	{
        allowlistedIdentities[identity] = true;
        emit IdentityAllowlisted(identity, msg.sender);
	}

    /**
     * @dev Remove a config mapping for identity
     * @param identity The identity hash to remove
     */
    function removeAllowlistedIdentity(bytes32 identity)
        public
        onlyOwner
    {
        delete allowlistedIdentities[identity];
    }

	function HashOnboardRequest(OnboardRequest memory req)
		public
		pure
		returns (bytes32 reqHash)
	{
		return keccak256(abi.encode(req.pubkey, req.nonce, req.operator, req.attestation));
	}


	function requestOnboard(OnboardRequest memory req)
		public
        onlyRole(ROLE_OPERATOR) /* Note: should be the instance rather than the operator */
		returns (bytes32 reqHash)
	{
		require(req.operator == msg.sender, "operator must be the sender");

		reqHash = HashOnboardRequest(req);
		onboardRequests[reqHash] = req;

		return reqHash;
	}

	function fetchOnboardRequest(bytes32 reqHash)
		public
		view
		returns (OnboardRequest memory)
	{
		return onboardRequests[reqHash];
	}

    /**
     * @dev Register a new instance domain
     * @param domain The domain name to register
     */
    function registerInstanceDomainName(string memory domain) 
        public 
        onlyRole(ROLE_OPERATOR) 
    {
        m_instanceDomainNames.push(domain);
        emit InstanceDomainRegistered(domain, msg.sender);
    }

	function InstanceDomainNames() public view returns (string[] memory) {
		return m_instanceDomainNames;
	}
}
