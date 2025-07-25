package hash

import (
	"golang.org/x/crypto/bcrypt"
)

// Cost уровень сложности bcrypt-хеширования (по умолчанию).
const Cost = bcrypt.DefaultCost

// HashPassword принимает обычный пароль и возвращает его bcrypt-хеш.
// Используется для хранения паролей в базе данных.
func HashPassword(plainPassword string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(plainPassword), Cost)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}

// CheckPasswordHash сравнивает bcrypt-хеш с паролем, введённым пользователем.
// Возвращает true, если пароль совпадает, иначе false.
func CheckPasswordHash(hashedPassword, plainPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword))
	return err == nil
}
