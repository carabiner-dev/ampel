package options

type SignerOptions struct{}

type SignerOptFn func(*SignerOptions) error
