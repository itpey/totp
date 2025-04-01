package totp

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
)

// Digits represents the number of digits to use.
type Digits int

const (
	// Constants for the number of digits.
	DigitsFour  Digits = 4
	DigitsFive  Digits = 5
	DigitsSix   Digits = 6
	DigitsEight Digits = 8
)

// Algorithm represents the hashing algorithm to use.
type Algorithm int

const (
	// Constants for supported algorithms.
	AlgorithmSHA1 Algorithm = iota
	AlgorithmSHA224
	AlgorithmSHA256
	AlgorithmSHA384
	AlgorithmSHA512
	AlgorithmSHA3_224
	AlgorithmSHA3_256
	AlgorithmSHA3_384
	AlgorithmSHA3_512
	AlgorithmBLAKE2S_256
	AlgorithmBLAKE2B_256
	AlgorithmBLAKE2B_384
	AlgorithmBLAKE2B_512
	AlgorithmMD5
)

// Config holds the configuration settings for hashing.
type Config struct {
	Algorithm Algorithm // Hashing algorithm to use (default: SHA1)
	Digits    Digits    // Number of output digits (default: 6)
	Period    int64     // Validity period in seconds (default: 30)
	Secret    string    // Base32 encoded secret key
	Skew      int64     // Time skew adjustment (default: 1)
}

// ConfigDefault is the default configuration.
var ConfigDefault = Config{
	Algorithm: AlgorithmSHA1, // Default algorithm
	Digits:    DigitsSix,     // Default number of digits
	Period:    30,            // Default validity period
	Skew:      1,             // Default skew
}

// hash returns a new hash.Hash based on the selected algorithm.
func (a Algorithm) hash() hash.Hash {
	switch a {
	case AlgorithmSHA1:
		return sha1.New()
	case AlgorithmSHA224:
		return sha256.New224()
	case AlgorithmSHA256:
		return sha256.New()
	case AlgorithmSHA384:
		return sha512.New384()
	case AlgorithmSHA512:
		return sha512.New()
	case AlgorithmSHA3_224:
		return sha3.New224()
	case AlgorithmSHA3_256:
		return sha3.New256()
	case AlgorithmSHA3_384:
		return sha3.New384()
	case AlgorithmSHA3_512:
		return sha3.New512()
	case AlgorithmBLAKE2S_256:
		h, _ := blake2s.New256(nil)
		return h
	case AlgorithmBLAKE2B_256:
		h, _ := blake2b.New256(nil)
		return h
	case AlgorithmBLAKE2B_384:
		h, _ := blake2b.New384(nil)
		return h
	case AlgorithmBLAKE2B_512:
		h, _ := blake2b.New512(nil)
		return h
	case AlgorithmMD5:
		return md5.New()
	default:
		return sha1.New()
	}
}

// configDefault sets default values for the provided configuration.
func configDefault(config ...Config) Config {
	// Return default config if no configuration is provided
	if len(config) < 1 {
		return ConfigDefault
	}

	// Override default config with provided values
	cfg := config[0]

	// Validate and set default values
	if cfg.Algorithm < AlgorithmSHA1 || cfg.Algorithm > AlgorithmMD5 {
		cfg.Algorithm = ConfigDefault.Algorithm
	}

	if cfg.Digits < DigitsFour || cfg.Digits > DigitsEight {
		cfg.Digits = ConfigDefault.Digits
	}

	if cfg.Period <= 0 {
		cfg.Period = ConfigDefault.Period
	}

	if cfg.Skew < 0 {
		cfg.Skew = ConfigDefault.Skew
	}

	return cfg
}
