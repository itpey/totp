# TOTP (Time-Based One-Time Password) Generator

![Go Version](https://img.shields.io/badge/Go-1.24%2B-blue)
![Go Reference](https://pkg.go.dev/badge/github.com/itpey/totp.svg)
![ReportCard](https://goreportcard.com/badge/github.com/itpey/totp)
![Coverage](https://coveralls.io/repos/github/itpey/totp/badge.svg?branch=main)
![License](https://img.shields.io/github/license/itpey/totp)

A high-performance and secure TOTP (Time-Based One-Time Password) generator and validator implemented in Go that supports multiple hashing algorithms, including SHA1, SHA256, SHA512, and BLAKE2.

## Features

- Efficient HMAC pooling to optimize performance.
- Supports multiple hashing algorithms (SHA1, SHA256, SHA512, BLAKE2, etc.).
- Customizable TOTP settings (digits, time period, skew allowance).
- Secure validation with constant-time comparison.

## Installation

```sh
go get -u github.com/itpey/totp
```

## Usage

### Generate a TOTP Code

```go
package main

import (
	"fmt"
	"time"

	"github.com/itpey/totp"
)

func main() {
	generator := totp.New(totp.Config{
		Secret:    "JBSWY3DPEHPK3PXP", // Base32 encoded secret key
		Algorithm: totp.AlgorithmSHA1,
		Digits:    totp.DigitsSix,
		Period:    30,
		Skew:      1,
	})

	code, err := generator.Generate()
	if err != nil {
		fmt.Println("Error generating TOTP:", err)
		return
	}

	fmt.Println("Generated TOTP Code:", code)
}
```

### Validate a TOTP Code

```go
valid, err := generator.Validate("123456")
if err != nil {
	fmt.Println("Validation error:", err)
} else if valid {
	fmt.Println("TOTP is valid!")
} else {
	fmt.Println("TOTP is invalid!")
}
```

## Configuration

| Field       | Type        | Default | Description                  |
| ----------- | ----------- | ------- | ---------------------------- |
| `Secret`    | `string`    | ---     | Base32 encoded secret key    |
| `Algorithm` | `Algorithm` | SHA1    | Hashing algorithm            |
| `Digits`    | `Digits`    | 6       | Number of digits in OTP      |
| `Period`    | `int64`     | 30      | Time step in seconds         |
| `Skew`      | `int64`     | 1       | Allowed time skew in periods |

## Supported Hashing Algorithms

- SHA1
- SHA224
- SHA256
- SHA384
- SHA512
- SHA3-224
- SHA3-256
- SHA3-384
- SHA3-512
- BLAKE2S-256
- BLAKE2B-256
- BLAKE2B-384
- BLAKE2B-512
- MD5

## Feedback and Contributions

If you encounter any issues or have suggestions for improvement, please [open an issue](https://github.com/itpey/totp/issues) on GitHub.

We welcome contributions! Fork the repository, make your changes, and submit a pull request.

## License

TOTP is open-source software released under the MIT License. You can find a copy of the license in the [LICENSE](https://github.com/itpey/totp/blob/main/LICENSE) file.

## Author

TOTP was created by [itpey](https://github.com/itpey)
