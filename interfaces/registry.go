package interfaces


type OnchainRegistryClient struct {
    *registry.Registry   // Embed the generated binding
    client *ethclient.Client
    address common.Address
}

func main() {
    // Connect to an Ethereum node
    client, err := ethclient.Dial("https://mainnet.infura.io/v3/YOUR_INFURA_KEY")
    if err != nil {
        log.Fatalf("Failed to connect to the Ethereum client: %v", err)
    }

    // For a new deployment
    auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
    if err != nil {
        log.Fatalf("Failed to create authorized transactor: %v", err)
    }

    address, tx, instance, err := registry.DeployRegistry(auth, client)
    if err != nil {
        log.Fatalf("Failed to deploy new registry contract: %v", err)
    }
    fmt.Printf("Contract deployed at: %s\n", address.Hex())

    // Or to connect to an existing contract
    address := common.HexToAddress("0x123abc...")
    instance, err := registry.NewRegistry(address, client)
    if err != nil {
        log.Fatalf("Failed to instantiate registry contract: %v", err)
    }

    // Now you can call contract methods
    // For example, to check if a DCAP is whitelisted:
    isWhitelisted, err := instance.IsDCAPWhitelisted(nil, dcapReport)
}
