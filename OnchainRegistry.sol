// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract Registry is AccessControl, Ownable {
    // Define roles as bytes32 constants
    bytes32 public constant ROLE_OPERATOR = keccak256("ROLE_OPERATOR");
    bytes32 public constant ROLE_METADATA = keccak256("ROLE_METADATA");
    bytes32 public constant ROLE_INSTANCE = keccak256("ROLE_INSTANCE");

    // Struct definitions
    struct Instance {
        string ip;
        bytes tlscert; // apps should use CA to connect unless connecting to a specific instance
    }

    struct DCAPReport {
        bytes32 mrTd;
        bytes32 mrImage;
        bytes32 mrOwner;
        bytes32 mrConfigId;
        bytes32 mrConfigOwner;
        bytes32[4] RTMRs;
    }

    // State variables
    Instance[] public instances;
    bytes public CA;
    bytes public CA_attestation;
    bytes public app_pubkey;
    bytes public app_pubkey_attestation;
    mapping(bytes32 => bytes) public configs;
    mapping(bytes32 => bytes) public encryptedSecrets;
    bytes32[] public registeredIdentities;
    mapping(bytes32 => bytes32) public instanceConfigMap;
    mapping(bytes32 => DCAPReport) public registeredDCAPReports;

    // Constructor
    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(ROLE_OPERATOR, msg.sender);
        _setupRole(ROLE_METADATA, msg.sender);
        _setupRole(ROLE_INSTANCE, msg.sender);
    }

    // Register a new instance
    function register(Instance memory i) public onlyRole(ROLE_OPERATOR) {
        instances.push(i);
    }

    // Set CA certificate and attestation
    function setCA(bytes memory ca, bytes memory ca_attestation) public onlyOwner {
        CA = ca;
        CA_attestation = ca_attestation;
    }

    // Set app public key and attestation
    function setAppPubkey(bytes memory pk, bytes memory pk_attestation) public onlyOwner {
        app_pubkey = pk;
        app_pubkey_attestation = pk_attestation;
    }

    // Add a new configuration
    function addConfig(bytes memory data) public onlyRole(ROLE_METADATA) {
        configs[keccak256(data)] = data;
    }

    // Add an encrypted secret
    function addSecret(bytes memory data) public onlyRole(ROLE_METADATA) {
        encryptedSecrets[keccak256(data)] = data;
    }

    // Helper function to calculate DCAP identity
    function DCAPIdentity(DCAPReport memory report) public view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this), report.RTMRs[0], report.mrImage));
    }

    // Set configuration for a DCAP report
    function setConfigForDCAP(DCAPReport memory report, bytes32 configHash) public onlyOwner {
        bytes32 identity = DCAPIdentity(report);
        registeredIdentities.push(identity);
        instanceConfigMap[identity] = configHash;
        registeredDCAPReports[identity] = report;
    }

    // Check if a DCAP report is whitelisted
    function IsDCAPWhitelisted(DCAPReport memory report) external view returns (bool) {
        bytes32 identity = DCAPIdentity(report);
        
        // Check if the identity exists in the registeredIdentities array
        for (uint i = 0; i < registeredIdentities.length; i++) {
            if (registeredIdentities[i] == identity) {
                return true;
            }
        }
        
        return false;
    }

    // Utility functions
    
    // Get the number of registered instances
    function getInstancesCount() public view returns (uint256) {
        return instances.length;
    }
    
    // Get an instance by index
    function getInstance(uint256 index) public view returns (Instance memory) {
        require(index < instances.length, "Index out of bounds");
        return instances[index];
    }
}
