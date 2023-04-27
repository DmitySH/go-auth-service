package log

import (
	"github.com/sirupsen/logrus"
)

var logger *logrus.Logger

func Logger() *logrus.Logger {
	if logger == nil {
		logger = logrus.New()
	}

	return logger
}

func SetLogrusLogger(newLogger *logrus.Logger) {
	logger = newLogger
}
