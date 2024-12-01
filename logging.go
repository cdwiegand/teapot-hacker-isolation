package teapot_hacker_isolation

import (
	"fmt"
	"os"
)

type MyTraefikLogger struct {
	prefix string
}

func NewMyTraefikLogger(prefix string) *MyTraefikLogger {
	return &MyTraefikLogger{
		prefix: prefix,
	}
}

func (logger *MyTraefikLogger) Error(message string) {
	os.Stderr.WriteString("ERROR: " + message)
}
func (logger *MyTraefikLogger) Errore(err error, message string) {
	logger.Error(fmt.Sprint(err) + ": " + message)
}
func (logger *MyTraefikLogger) Errorf(format string, v ...any) {
	logger.Error(fmt.Sprintf(format, v...))
}
func (logger *MyTraefikLogger) Erroref(err error, format string, v ...any) {
	logger.Error(fmt.Sprint(err) + ": " + fmt.Sprintf(format, v...))
}

func (logger *MyTraefikLogger) Warn(message string) {
	os.Stderr.WriteString("WARN: " + message)
}
func (logger *MyTraefikLogger) Warne(err error, message string) {
	logger.Warn(fmt.Sprint(err) + ": " + message)
}
func (logger *MyTraefikLogger) Warnf(format string, v ...any) {
	logger.Warn(fmt.Sprintf(format, v...))
}
func (logger *MyTraefikLogger) Warnef(err error, format string, v ...any) {
	logger.Warn(fmt.Sprint(err) + ": " + fmt.Sprintf(format, v...))
}

func (logger *MyTraefikLogger) Info(message string) {
	os.Stdout.WriteString("INFO: " + message)
}
func (logger *MyTraefikLogger) Infoe(err error, message string) {
	logger.Info(fmt.Sprint(err) + ": " + message)
}
func (logger *MyTraefikLogger) Infof(format string, v ...any) {
	logger.Info(fmt.Sprintf(format, v...))
}
func (logger *MyTraefikLogger) Infoef(err error, format string, v ...any) {
	logger.Info(fmt.Sprint(err) + ": " + fmt.Sprintf(format, v...))
}

func (logger *MyTraefikLogger) Debug(message string) {
	os.Stdout.WriteString("DEBUG: " + message)
}
func (logger *MyTraefikLogger) Debuge(err error, message string) {
	logger.Debug(fmt.Sprint(err) + ": " + message)
}
func (logger *MyTraefikLogger) Debugf(format string, v ...any) {
	logger.Debug(fmt.Sprintf(format, v...))
}
func (logger *MyTraefikLogger) Debugef(err error, format string, v ...any) {
	logger.Debug(fmt.Sprint(err) + ": " + fmt.Sprintf(format, v...))
}
