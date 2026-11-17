package tamper

import "crypto/ed25519"

func ed25519FromSeed(seed []byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(seed) }
