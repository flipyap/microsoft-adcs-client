package client

type Certificates struct {
	ID                  string `json:"id"`
	CertificateB64      string `json:"certificate_b64"`
	CertificateChainB64 string `json:"certificate_chain_b64"`
	// CertificateBin      string `json:"certificate_bin"`
	// CertificateChainBin string `json:"certificate_chain_bin"`
}
