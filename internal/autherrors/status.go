package autherrors

type Status string

const (
	UserExists          Status = "user already exists"
	UserNotExists       Status = "user doesn't exist"
	UserInvalidPassword Status = "user password is invalid"

	InvalidToken Status = "token is invalid"
	InvalidEmail Status = "email is invalid"
	WeakPassword Status = "password is too weak"
)

type st interface {
	Status() Status
}
