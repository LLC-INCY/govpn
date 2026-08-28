package logutil

import "log"

type Logger struct{ logger *log.Logger }

func New(logger *log.Logger) *Logger { return &Logger{logger: logger} }

func (l *Logger) Printf(format string, arguments ...any) {
	if l != nil && l.logger != nil {
		l.logger.Printf(format, arguments...)
	}
}
