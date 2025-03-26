package interfaces

type TLSCSR []byte;
type TLSCert []byte;
type CACert []byte;
type AppPubkey []byte;
type AppPrivkey []byte;
type Attestation []byte;
type ContractAddress [20]byte;

type DCAPReport struct {}

type AppKMS interface {
	// Public
	GetCA(ContractAddress) (CACert, Attestation, error)
	GetAppPubkey(ContractAddress) (AppPubkey, Attestation, error)
	// Verifies identity is allowed
	GetAppPrivkey(ContractAddress, DCAPReport) (AppPrivkey, error)
	SignCSR(ContractAddress, DCAPReport, TLSCSR) (TLSCert, error)
}

type MockKMS struct {
	Privkey []byte
}

func (k *MockKMS) GetCA(ContractAddress) (CACert, Attestation, error) {
	return nil, nil, nil
}

func (k *MockKMS) GetAppPubkey(ContractAddress) (AppPubkey, Attestation, error) {
	return nil, nil, nil
}

func (k *MockKMS) GetAppPrivkey(ContractAddress, DCAPReport) (AppPrivkey, error) {
	return nil, nil
}

func (k *MockKMS) SignCSR(ContractAddress, DCAPReport, TLSCSR) (TLSCert, error) {
	return nil, nil
}
