package repository

import (
	"fmt"
	"github.com/jmoiron/sqlx"
)

type DBConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	DBName   string
	SSLMode  string
}

func NewPostgresDB(cfg DBConfig) (*sqlx.DB, error) {
	db, connectErr := sqlx.Connect("postgres",
		fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=%s",
			cfg.Host, cfg.Port, cfg.Username, cfg.DBName, cfg.Password, cfg.SSLMode))
	if connectErr != nil {
		return nil, fmt.Errorf("can't connect to postgres: %w", connectErr)
	}

	return db, nil
}
