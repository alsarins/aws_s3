package main

import (
	"io"
	"log"
	"os"
)

var InfoLogger *log.Logger
var ErrorLogger *log.Logger
var TraceLogger *log.Logger

const LogInfoPrefix = "INFO  "
const LogErrorPrefix = "ERROR "
const LogTracePrefix = "TRACE "

func makeLogger(output io.Writer, prefix string) *log.Logger {
	return log.New(output, prefix, log.LstdFlags|log.Lshortfile|log.Lmicroseconds)
}

func init() {
	InfoLogger = makeLogger(io.Discard, LogInfoPrefix)
	ErrorLogger = makeLogger(os.Stderr, LogErrorPrefix)
}

func enableDebugMode(debugLevel string) {
	var infoOutput = io.Discard
	var traceOutput = io.Discard

	switch debugLevel {
	case "true":
		infoOutput = os.Stdout
	case "trace":
		infoOutput = os.Stdout
		traceOutput = os.Stdout
	}

	InfoLogger = makeLogger(infoOutput, LogInfoPrefix)
	TraceLogger = makeLogger(traceOutput, LogTracePrefix)
}
