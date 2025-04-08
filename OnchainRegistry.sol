// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

struct DCAPEvent {
	uint32 Index;
	uint32 EventType;
	bytes EventPayload;
	bytes32 Digest;
}

struct DCAPReport {
	bytes32 mrTd;          // Measurement register for TD
	bytes32[4] RTMRs;      // Runtime measurement registers
	bytes32 mrOwner;       // Measurement register for owner
	bytes32 mrConfigId;    // Measurement register for config ID
	bytes32 mrConfigOwner; // Measurement register for config owner
}

struct MAAReport {
	bytes32[24] PCRs;
}

struct AppPKI {
	bytes ca;
	bytes pubkey;
	bytes attestation;
}

// Interface needed by the provisioning backend
interface IRegistry {
    // Identity computation from attestation reports
    function DCAPIdentity(DCAPReport memory report, DCAPEvent[] memory eventLog) external view returns (bytes32);
    function MAAIdentity(MAAReport memory report) external view returns (bytes32);

    // Configuration mapping for identity
    function getConfigForIdentity(bytes32 identity) external view returns (bytes32);

    // Storage backend management
    function allStorageBackends() external view returns (string[] memory);

    // Optional: If artifacts are stored on-chain
    function getArtifact(bytes32 artifactHash) external view returns (bytes memory);

    // Optional: PKI information
    function getPKI() external view returns (AppPKI memory);
}

/**
 * @title Registry
 * @dev A contract for managing trusted execution environment (TEE) identities and configurations
 * using Intel DCAP attestation.
 */
contract Registry is AccessControl, Ownable, ReentrancyGuard, IRegistry {
    // Define roles as bytes32 constants
    bytes32 public constant ROLE_OPERATOR = keccak256("ROLE_OPERATOR");
    bytes32 public constant ROLE_METADATA = keccak256("ROLE_METADATA");
    bytes32 public constant ROLE_INSTANCE = keccak256("ROLE_INSTANCE");

    // Maximum size for byte arrays to prevent DoS attacks
    uint256 public constant MAX_BYTES_SIZE = 20 * 1024; // 20KB limit

    // State variables
    string[] public instanceDomainNames;
	AppPKI public app_pki;

	// Notes config and secrets locations
	string[] public storageBackends;
    // Maps config hash to config data and secrets for onchain DA
    mapping(bytes32 => bytes) public artifacts;
    // Maps identity to config hash
    mapping(bytes32 => bytes32) public identityConfigMap;

    // Events
    event InstanceDomainRegistered(string domain, address registrar);
	event StorageBackendSet(string location, address setter);
	event StorageBackendRemoved(string location, address remover);
    event ArtifactAdded(bytes32 configHash, address adder);
    event PKIUpdated(address updater, AppPKI pki);
    event IdentityConfigSet(bytes32 identity, bytes32 configHash, address setter);

    /**
     * @dev Constructor to set up initial roles.
     */
    constructor() Ownable(msg.sender) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ROLE_OPERATOR, msg.sender);
        _grantRole(ROLE_METADATA, msg.sender);
        _grantRole(ROLE_INSTANCE, msg.sender);
    }

    /**
     * @dev Modifier to check if input bytes size is within limits
     */
    modifier limitBytesSize(bytes memory data) {
        require(data.length <= MAX_BYTES_SIZE, "Data size exceeds limit");
        _;
    }

    /**
     * @dev Register a new instance domain
     * @param domain The domain name to register
     */
    function registerInstanceDomainName(string memory domain) 
        public 
        onlyRole(ROLE_OPERATOR) 
    {
        instanceDomainNames.push(domain);
        emit InstanceDomainRegistered(domain, msg.sender);
    }

	function allInstanceDomainNames() public view returns (string[] memory) {
		return instanceDomainNames;
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

    function getPKI() external view returns (AppPKI memory) {
		return app_pki;
	}

	// Add a new content location or update an existing one
	function setStorageBackend(
		string memory backendLocation
	)
		public
		onlyOwner
	{
		storageBackends.push(backendLocation);
		emit StorageBackendSet(backendLocation, msg.sender);
	}

	// Remove a content location
	function removeStorageBackend(
		string memory backendLocation
	)
		public
		onlyOwner
	{
        for (uint i = 0; i < storageBackends.length; i++) {
            if (keccak256(abi.encodePacked(storageBackends[i])) == keccak256(abi.encodePacked(backendLocation))) {
                storageBackends[i] = storageBackends[storageBackends.length - 1];
                storageBackends.pop();
                break;
            }
        }
		emit StorageBackendRemoved(backendLocation, msg.sender);
	}

	/**
	 * @dev Get the number of storage backends
	 * @return The length of the storageBackends array
	 */
	function allStorageBackends()
		public
		view
		returns (string[] memory)
	{
		return storageBackends;
	}

    /**
     * @dev Add a new onchain artifact
     * @param data The data to store (configuration or encrypted secret)
     * @return artifactHash The hash of the added artifact
     */
    function addArtifact(bytes memory data) 
        public 
        onlyRole(ROLE_METADATA) 
        limitBytesSize(data)
        returns (bytes32 artifactHash) 
    {
        artifactHash = sha256(data);
        artifacts[artifactHash] = data;
        emit ArtifactAdded(artifactHash, msg.sender);
        return artifactHash;
    }

    /**
     * @dev Fetch an artifact
     * @param artifactHash The object to fetch
     */
    function getArtifact(bytes32 artifactHash) 
        external view
        returns (bytes memory data) 
    {
        require(artifacts[artifactHash].length > 0, "Artifact does not exist");
        return artifacts[artifactHash];
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

    /**
     * @dev Set configuration for a DCAP report
     * @param report The DCAP report
     * @param eventLog The runtime event log (extensions)
     * @param configHash The configuration hash to associate
     */
    function setConfigForDCAP(DCAPReport memory report, DCAPEvent[] memory eventLog, bytes32 configHash) 
        public 
        onlyOwner 
        nonReentrant
    {
        bytes32 identity = DCAPIdentity(report, eventLog);
		setConfigForIdentity(identity, configHash);
    }

    /**
     * @dev Set configuration for a DCAP report
     * @param report The MAA report
     * @param configHash The configuration hash to associate
     */
    function setConfigForMAA(MAAReport memory report, bytes32 configHash) 
        public 
        onlyOwner 
        nonReentrant
    {
        bytes32 identity = MAAIdentity(report);
		setConfigForIdentity(identity, configHash);
    }

	function setConfigForIdentity(bytes32 identity, bytes32 configHash)
		private
	{
        identityConfigMap[identity] = configHash;
        emit IdentityConfigSet(identity, configHash, msg.sender);
	}

    /**
     * @dev Return config id for an identity
     * @param identity The identity
     */
    function getConfigForIdentity(bytes32 identity) external view returns (bytes32) {
		require(identityConfigMap[identity] != bytes32(0), "Config not mapped");
		return identityConfigMap[identity];
	}

    /**
     * @dev Remove a config mapping for identity
     * @param identity The identity hash to remove
     */
    function removeConfigMapForIdentity(bytes32 identity)
        public
        onlyOwner
    {
        delete identityConfigMap[identity];
    }
}
