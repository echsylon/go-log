package log

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

// The Unix Syslog log levels complemented with a custom "trace" level.
const (
	LOG_LEVEL_EMERGENCY = iota
	LOG_LEVEL_ALERT
	LOG_LEVEL_CRITICAL
	LOG_LEVEL_ERROR
	LOG_LEVEL_WARNING
	LOG_LEVEL_NOTICE
	LOG_LEVEL_INFORMATIONAL
	LOG_LEVEL_DEBUG
	LOG_LEVEL_TRACE
)

// The default types of information the caller can configure the logger to
// print along with each log message. See "SetLogColumns" for details.
const (
	LOG_COLUMN_DATETIME = iota
	LOG_COLUMN_PID
	LOG_COLUMN_SOURCE
	LOG_COLUMN_LEVEL
)

const (
	reset           = "\033[0m"
	blue_fg_16      = "\033[94m"
	blue_fg_bg_16   = "\033[34;104m"
	gray_fg_16      = "\033[90m"
	gray_fg_bg_16   = "\033[37;100m"
	red_fg_16       = "\033[91m"
	red_fg_bg_16    = "\033[31;101m"
	yellow_fg_16    = "\033[93m"
	yellow_fg_bg_16 = "\033[33;103m"
)

type configuration struct {
	logLevel      int
	logColumns    []func() string
	logColumnGlue string
	colorsEnabled bool
}

var logLevelString func() string
var config configuration

func init() {
	config = configuration{
		logLevel:      LOG_LEVEL_DEBUG,
		logColumns:    []func() string{getTimeColumn, getPidColumn, getFrameColumn, getLogLevelColumn},
		logColumnGlue: "  ",
		colorsEnabled: areColorsEnabled(),
	}
}

// SetLogLevel constrains which logs to print. All log categories associated
// with a log level lower than or equal to the value being defined here will
// be sent to the output streams.
func SetLogLevel(level int) {
	config.logLevel = level
}

// SetLogColumns will alter the information being printed before each log
// message. This function takes either a "LOG_COLUMN_..." constant that
// describes one of the standard log parameters, or a function that takes
// no arguments but produces a string "func() string" in order to log custom
// information.
func SetLogColumns(columns ...any) {
	config.logColumns = []func() string{}
	for _, column := range columns {
		switch c := column.(type) {
		case func() string:
			config.logColumns = append(config.logColumns, c)
		case int:
			switch c {
			case LOG_COLUMN_DATETIME:
				config.logColumns = append(config.logColumns, getTimeColumn)
			case LOG_COLUMN_PID:
				config.logColumns = append(config.logColumns, getPidColumn)
			case LOG_COLUMN_SOURCE:
				config.logColumns = append(config.logColumns, getFrameColumn)
			case LOG_COLUMN_LEVEL:
				config.logColumns = append(config.logColumns, getLogLevelColumn)
			}
		}
	}
}

// SetLogColumnSeparator defines how the log info columns are separated.
// If the logs are to be machine processed at a later time, this function
// enables producing, say, a CSV file by setting the separator ";" or "\t".
func SetLogColumnSeparator(separator string) {
	config.logColumnGlue = separator
}

// DisableColorOutput prevents the logs from sending color control characters
// to the output stream.
//
// Color output is usually enabled by default, unless it is actively disabled
// by FORCE_COLOR or NO_COLOR environment variables. This logger honors said
// variables without the caller having to explicitly call this method.
//
// Furthermore, this logger will also disable color output when log output is
// redirected (through any of the ">" directives) to a different destination
// than the terminal.
func DisableColorOutput() {
	config.colorsEnabled = false
}

// Emergency prints a panic mode log message. These logs are usually printed
// when the system is unusable due to a panic situation. This function will
// not actually "panic()", allowing the process to do additional logging or
// tombstone aggregation.
func Emergency(message string, args ...any) {
	if config.logLevel < LOG_LEVEL_EMERGENCY {
		return
	} else if !config.colorsEnabled || !isTerminal(os.Stderr) {
		logLevelString = func() string { return " P " }
		print(os.Stderr, message, args...)
	} else {
		logLevelString = func() string { return redOnRed(" P ") }
		print(os.Stderr, red(message), args...)
	}
}

// Alert prints a log message for situations where an action must be taken
// immediately, say, for example, due to a corrup database. This function
// will not "panic()", allowing the process to do additional logging.
func Alert(message string, args ...any) {
	if config.logLevel < LOG_LEVEL_ALERT {
		return
	} else if !config.colorsEnabled || !isTerminal(os.Stderr) {
		logLevelString = func() string { return " A " }
		print(os.Stderr, message, args...)
	} else {
		logLevelString = func() string { return redOnRed(" A ") }
		print(os.Stderr, red(message), args...)
	}
}

// Critical prints a log message for critical errors, such as hardware device
// errors. This function will not "panic()", allowing the process to do
// additional logging.
func Critical(message string, args ...any) {
	if config.logLevel < LOG_LEVEL_CRITICAL {
		return
	} else if !config.colorsEnabled || !isTerminal(os.Stderr) {
		logLevelString = func() string { return " C " }
		print(os.Stderr, message, args...)
	} else {
		logLevelString = func() string { return redOnRed(" C ") }
		print(os.Stderr, red(message), args...)
	}
}

// Error prints a log message for serious errors that may cause a degrade in
// functionality or even data loss without having to halt execution, for
// example a full disk. This function will not "panic()", allowing the
// process to do additional logging.
func Error(message string, args ...any) {
	if config.logLevel < LOG_LEVEL_ERROR {
		return
	} else if !config.colorsEnabled || !isTerminal(os.Stderr) {
		logLevelString = func() string { return " E " }
		print(os.Stderr, message, args...)
	} else {
		logLevelString = func() string { return redOnRed(" E ") }
		print(os.Stderr, red(message), args...)
	}
}

// Warning prints a log message for issues that are not necessarily errors
// in them selves, but indicates other logical issues, for example when
// trying to remove an item from an empty list.
func Warning(message string, args ...any) {
	if config.logLevel < LOG_LEVEL_WARNING {
		return
	} else if !config.colorsEnabled || !isTerminal(os.Stdout) {
		logLevelString = func() string { return " W " }
		print(os.Stdout, message, args...)
	} else {
		logLevelString = func() string { return yellowOnYellow(" W ") }
		print(os.Stdout, yellow(message), args...)
	}
}

// Notice prints a log message for situations that are normal but needs
// special handling, for example when requesting a network resource that
// is temporarily unavailable.
func Notice(message string, args ...any) {
	if config.logLevel < LOG_LEVEL_NOTICE {
		return
	} else if !config.colorsEnabled || !isTerminal(os.Stdout) {
		logLevelString = func() string { return " N " }
		print(os.Stdout, message, args...)
	} else {
		logLevelString = func() string { return yellowOnYellow(" N ") }
		print(os.Stdout, yellow(message), args...)
	}
}

// Information prints a log message that confirms expected execution, for
// example when data has been successfully saved.
func Information(message string, args ...any) {
	if config.logLevel < LOG_LEVEL_INFORMATIONAL {
		return
	} else if !config.colorsEnabled || !isTerminal(os.Stdout) {
		logLevelString = func() string { return " I " }
		print(os.Stdout, message, args...)
	} else {
		logLevelString = func() string { return blueOnBlue(" I ") }
		print(os.Stdout, blue(message), args...)
	}
}

// Debug prints a log message which contains information that is normally
// useful only when debugging a program, for example an intermediate value
// of local variable.
func Debug(message string, args ...any) {
	if config.logLevel < LOG_LEVEL_DEBUG {
		return
	} else if !config.colorsEnabled || !isTerminal(os.Stdout) {
		logLevelString = func() string { return " D " }
		print(os.Stdout, message, args...)
	} else {
		logLevelString = func() string { return grayOnGray(" D ") }
		print(os.Stdout, gray(message), args...)
	}
}

// Trace prints a debug log message that gives information of the execution
// flow during debugging. This is useful when trying to debug exactly which
// logical branch the logic is following.
func Trace(message string, args ...any) {
	if config.logLevel < LOG_LEVEL_TRACE {
		return
	} else if !config.colorsEnabled || !isTerminal(os.Stdout) {
		logLevelString = func() string { return " T " }
		print(os.Stdout, message, args...)
	} else {
		logLevelString = func() string { return grayOnGray(" T ") }
		print(os.Stdout, gray(message), args...)
	}
}

func print(stream *os.File, message string, args ...any) {
	var builder strings.Builder
	for _, function := range config.logColumns {
		if function != nil {
			if column := function(); column != "" {
				builder.WriteString(column)
				builder.WriteString(config.logColumnGlue)
			}
		}
	}

	builder.WriteString(message)
	if !strings.HasSuffix(message, "\n") {
		builder.WriteString("\n")
	}

	format := builder.String()
	fmt.Fprintf(stream, format, args...)
}

func getTimeColumn() string {
	return time.Now().Format(time.DateTime)
}

func getPidColumn() string {
	return fmt.Sprintf("%d", os.Getpid())
}

func getFrameColumn() string {
	// We want to get the frame in the call stack that called the exposed
	// log function in this file. Since we're 3 frames deep at this point
	// we need to traverse in the callstack accordingly.
	if _, file, line, ok := runtime.Caller(3); !ok {
		return "???"
	} else {
		fileName := filepath.Base(file)
		fileRef := fmt.Sprintf("%s:%d", fileName, line)
		length := len(fileRef)
		max := 24
		if length > max {
			start := length - max + 1
			fileRef = fmt.Sprintf("…%s", fileRef[start:])
		}
		return fmt.Sprintf("%*s", max, fileRef)
	}
}

func getLogLevelColumn() string {
	return logLevelString()
}

func blue(text string) string {
	return blue_fg_16 + text + reset
}

func blueOnBlue(text string) string {
	return blue_fg_bg_16 + text + reset
}

func gray(text string) string {
	return gray_fg_16 + text + reset
}

func grayOnGray(text string) string {
	return gray_fg_bg_16 + text + reset
}

func yellow(text string) string {
	return yellow_fg_16 + text + reset
}

func yellowOnYellow(text string) string {
	return yellow_fg_bg_16 + text + reset
}

func red(text string) string {
	return red_fg_16 + text + reset
}

func redOnRed(text string) string {
	return red_fg_bg_16 + text + reset
}

func areColorsEnabled() bool {
	forceColor, present := os.LookupEnv("FORCE_COLOR")
	if present {
		forceColorInt, err := strconv.ParseInt(forceColor, 10, 8)
		if err == nil {
			return forceColorInt > 0
		} else if forceColor == "false" {
			return false
		} else if forceColor == "true" {
			return true
		} else if forceColor == "" {
			return true
		}
	}

	forceNoColor, present := os.LookupEnv("NO_COLOR")
	if present {
		if forceNoColor == "" {
			return false
		} else if forceNoColor == "true" {
			return false
		}
	}

	// Just assume all terminals support at least 8 colors. Otherwise, one
	// could start to analyze the TERM env variable and try to draw further
	// conclusions from there. As a last resort, the caller can always
	// forcefully disable colors by calling "DisableColorOutput()".
	return true
}

func isTerminal(stream *os.File) bool {
	return term.IsTerminal(int(stream.Fd()))
}
