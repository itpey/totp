package totp_test

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/itpey/totp"
)

type tc struct {
	TS     int64
	TOTP   string
	Mode   totp.Algorithm
	Secret string
}

var (
	secSha1   = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	secSha256 = base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	secSha512 = base32.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))

	rfcMatrixTCs = []tc{
		{59, "94287082", totp.AlgorithmSHA1, secSha1},
		{59, "46119246", totp.AlgorithmSHA256, secSha256},
		{59, "90693936", totp.AlgorithmSHA512, secSha512},
		{1111111109, "07081804", totp.AlgorithmSHA1, secSha1},
		{1111111109, "68084774", totp.AlgorithmSHA256, secSha256},
		{1111111109, "25091201", totp.AlgorithmSHA512, secSha512},
		{1111111111, "14050471", totp.AlgorithmSHA1, secSha1},
		{1111111111, "67062674", totp.AlgorithmSHA256, secSha256},
		{1111111111, "99943326", totp.AlgorithmSHA512, secSha512},
		{1234567890, "89005924", totp.AlgorithmSHA1, secSha1},
		{1234567890, "91819424", totp.AlgorithmSHA256, secSha256},
		{1234567890, "93441116", totp.AlgorithmSHA512, secSha512},
		{2000000000, "69279037", totp.AlgorithmSHA1, secSha1},
		{2000000000, "90698825", totp.AlgorithmSHA256, secSha256},
		{2000000000, "38618901", totp.AlgorithmSHA512, secSha512},
		{20000000000, "65353130", totp.AlgorithmSHA1, secSha1},
		{20000000000, "77737706", totp.AlgorithmSHA256, secSha256},
		{20000000000, "47863826", totp.AlgorithmSHA512, secSha512},
	}
)

func TestValidateRFCMatrix(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		cfg := totp.Config{
			Secret:    tx.Secret,
			Digits:    totp.DigitsEight,
			Period:    30,
			Skew:      0,
			Algorithm: tx.Mode,
		}
		generator := totp.New(cfg)

		valid, err := generator.ValidateForTime(tx.TOTP, time.Unix(tx.TS, 0).UTC())
		if err != nil {
			t.Errorf("Error validating TOTP for time %d: %v", tx.TS, err)
		}
		if !valid {
			t.Errorf("TOTP %s was not valid for time %d", tx.TOTP, tx.TS)
		}
	}
}

func TestGenerateRFCTCs(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		cfg := totp.Config{
			Secret:    tx.Secret,
			Digits:    totp.DigitsEight,
			Period:    30,
			Skew:      0,
			Algorithm: tx.Mode,
		}
		generator := totp.New(cfg)

		passcode, err := generator.GenerateForTime(time.Unix(tx.TS, 0).UTC())
		if err != nil {
			t.Errorf("Error generating TOTP for time %d: %v", tx.TS, err)
			continue
		}
		if passcode != tx.TOTP {
			t.Errorf("Expected TOTP %s, but got %s for time %d", tx.TOTP, passcode, tx.TS)
		}
	}
}

func TestValidateSkew(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	tests := []tc{
		{29, "94287082", totp.AlgorithmSHA1, secSha1},
		{59, "94287082", totp.AlgorithmSHA1, secSha1},
		{61, "94287082", totp.AlgorithmSHA1, secSha1},
	}
	for _, tx := range tests {

		cfg := totp.Config{
			Secret:    tx.Secret,
			Digits:    totp.DigitsEight,
			Period:    30,
			Skew:      1,
			Algorithm: tx.Mode,
		}
		generator := totp.New(cfg)

		valid, err := generator.ValidateForTime(tx.TOTP, time.Unix(tx.TS, 0).UTC())
		if err != nil {
			t.Errorf("Error validating TOTP for time %d: %v", tx.TS, err)
		}
		if !valid {
			t.Errorf("TOTP %s was not valid for time %d", tx.TOTP, tx.TS)
		}
	}
}

func BenchmarkGenerate(b *testing.B) {
	totp := totp.New(totp.Config{
		Secret:    "JBSWY3DPEHPK3PXP",
		Digits:    6,
		Period:    30,
		Skew:      1,
		Algorithm: totp.AlgorithmSHA1,
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = totp.Generate()
	}
}

func BenchmarkValidate(b *testing.B) {
	totp := totp.New(totp.Config{
		Secret:    "JBSWY3DPEHPK3PXP",
		Digits:    6,
		Period:    30,
		Skew:      1,
		Algorithm: totp.AlgorithmSHA1,
	})

	code, _ := totp.Generate()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = totp.Validate(code)
	}
}
