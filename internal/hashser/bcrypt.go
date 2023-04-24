package hashser

import (
	"golang.org/x/crypto/bcrypt"
)

type BcryptHasher struct {
	cost int
}

func (h *BcryptHasher) Hash(toHash string) (string, error) {
	hashed, hashErr := bcrypt.GenerateFromPassword([]byte(toHash), h.cost)
	if hashErr != nil {
		return "", hashErr
	}

	return string(hashed), nil
}

func (h *BcryptHasher) CompareHashes(notHashed string, hashed string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(notHashed)) == nil
}

func NewBcryptHasher(cost int) *BcryptHasher {
	return &BcryptHasher{cost: cost}
}
