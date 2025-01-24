package openeox

import "time"

type EOX = EOX020

type EOX020 struct {
	*Product

	// Schema version, always  https://openeox.org/schema-0.2.0.json
	Schema string `json:"$schema"`

	// SupplierID contains a unique identifier for the supplier or service
	// provider. It is a string with a minimum length of 1 character.
	// Note: The exact usage and proper identifying method of this field
	// is currently under discussion in the community (see #6).
	// As a CSAF issuing party, you could use the value /document/publisher/namespace.
	SupplierID         string     `json:"supplierId"`
	SupplierName       string     `json:"supplierName"`
	EOLDate            *time.Time `json:"EOLDate"`
	ReplacementProduct *Product   `json:"replacementProduct,omitempty"`
}

type Product struct {
	ProductId      string `json:"productId"`
	ProductName    string `json:"productName"`
	ProductVersion string `json:"productVersion"`
}
