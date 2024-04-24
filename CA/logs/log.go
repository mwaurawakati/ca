package logs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	es "github.com/elastic/go-elasticsearch/v8"
)

// configuration for logging
type configType struct {
	// elastic search configuration
	ElasticSearchConfiguration struct {
		Addresses []string `json:"addresses"`
		APIKey    string   `json:"api_key"`
		Username  string   `json:"username"`
		Password  string   `json:"password"`
		CloudID   string   `json:"cloud_id"`
	} `json:"elastic_configuration"`
	// ElasticSearch enabling
	ElasticSearchEnabled bool `json:"elastic_enabled"`
	// Log level
	Level string `json:"level"`
	// elasticsearch log level
	ElasticLevel string `json:"elastic_level"`
	AddSource    bool   `json:"add_source"`
}

// custom log levels
const (
	LevelTrace = slog.Level(-8)

	LevelNotice = slog.Level(2)

	LevelCritical = slog.Level(12)
)

type programLogLevel struct {
	slog.LevelVar
}

// ProgramLogLevel is a program log level
// nolint: gochecknoglobals
var ProgramLogLevel programLogLevel

// logger implements a simple io.Writer interface for logging
type logger struct {
	W          chan []byte
	ESClient   *es.Client
	ESLogLevel slog.Level
	mu         sync.Mutex // guards
}

// This write send data to a channel to be recorded in
func (l *logger) Write(data []byte) (int, error) {
	// Function to check if the channel is open for sending
	isChannelOpen := func(ch <-chan []byte) bool {
		select {
		case <-ch:
			return false // Channel is closed
		default:
			return true // Channel is open
		}
	}
	// send log messsage to channel for being recorded in elastic search
	if isChannelOpen(l.W) {
		l.W <- data
	}
	return os.Stdout.Write(data)
}

// Logger is the logger
// nolint: gochecknoglobals
var Logger logger

// LoggerChan is the loggerchannel
// nolint: gochecknoglobals
var LoggerChan chan []byte

// nolint: gochecknoinits
func init() {
	LoggerChan = make(chan []byte)
	Logger = logger{W: LoggerChan}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: &ProgramLogLevel, AddSource: true})))
}

// nolint: revive
func (l *logger) Process() {
	for {
		data := <-l.W

		var d map[string]any
		l.mu.Lock()
		err := json.Unmarshal(data, &d)
		if err != nil {
			slog.Error(err.Error())
		}
		l.mu.Unlock()
		// record only the log level above the set log level
		if (d["level"] != nil) && LogLevel(d["level"].(string)) >= l.ESLogLevel {
			res, err := l.ESClient.Index("rum", bytes.NewReader(data))
			if err != nil {
				Critical("Unable to save data in elastic" + err.Error())
			}
			if res.IsError() {
				slog.Debug(fmt.Errorf("elasticsearch error: %s", res.String()).Error())
			}
			res.Body.Close()
		}
	}
}

// nolint: gochecknoglobals, revive
func ReplaceAttr(_ []string, a slog.Attr) slog.Attr {
	// Customize the name of the level key and the output string, including
	// custom level values.
	if a.Key == slog.LevelKey {
		// Handle custom level values.
		// nolint: errcheck, revive
		level := a.Value.Any().(slog.Level)

		// This could also look up the name from a map or other structure, but
		// this demonstrates using a switch statement to rename levels. For
		// maximum performance, the string values should be constants, but this
		// example uses the raw strings for readability.
		switch {
		case level < slog.LevelDebug:
			a.Value = slog.StringValue("TRACE")
		case level < slog.LevelInfo:
			a.Value = slog.StringValue("DEBUG")
		case level < LevelNotice:
			a.Value = slog.StringValue("INFO")
		case level < slog.LevelWarn:
			a.Value = slog.StringValue("NOTICE")
		case level < slog.LevelError:
			a.Value = slog.StringValue("WARNING")
		case level < LevelCritical:
			a.Value = slog.StringValue("ERROR")
		default:
			a.Value = slog.StringValue("CRITICAL")
		}
	}

	return a
}

// nolint: revive
func NewElasticSearchClient(config es.Config) (*es.Client, error) {
	return es.NewClient(config)
}

// nolint: revive
func Notice(msg string, args ...interface{}) {
	slog.Log(context.Background(), LevelNotice, msg, args...)
}

// nolint: revive
func NewLogHandler(useElasticSearch, addSource bool) *slog.TextHandler {
	if useElasticSearch {
		return slog.NewTextHandler(&Logger, &slog.HandlerOptions{AddSource: addSource, Level: &ProgramLogLevel})
	}
	return slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{AddSource: addSource, Level: &ProgramLogLevel})
}

// nolint: revive
func InitLogger(jsonconfig json.RawMessage) {
	// Unmarshal config
	var err error
	var config configType
	if len(jsonconfig) < 2 {
		slog.Error("Log Missing Configuration")
		slog.Warn("Using default std logger")
		slog.Warn("No configuration for Elastic search")
		return
	}
	if err = json.Unmarshal(jsonconfig, &config); err != nil {
		slog.Error("Logger failed to parse config: " + err.Error())
		slog.Warn("Using default std logger")
		slog.Warn("No configuration for Elastic search")
		return
	}
	// set program log level
	ProgramLogLevel.Set(LogLevel(config.Level))
	slog.Debug(ProgramLogLevel.String())
	// Start elastic search if enabled
	if config.ElasticSearchEnabled {
		c := es.Config{
			Addresses: config.ElasticSearchConfiguration.Addresses,
			APIKey:    config.ElasticSearchConfiguration.APIKey,
			Username:  config.ElasticSearchConfiguration.Username,
			Password:  config.ElasticSearchConfiguration.Password,
			CloudID:   config.ElasticSearchConfiguration.CloudID,
		}
		esc, err := NewElasticSearchClient(c)
		if err != nil {
			slog.Error("Logger failed to connect to elastic search: " + err.Error())
			slog.Warn("Using default std logger")
			slog.Warn("No connection to Elastic search")
			Notice("Logs will not be sent to elastic search")
			return
		}
		Logger.ESClient = esc
		// send  logs to elasticsearch in a go routine
		go Logger.Process()
		i, err := Logger.ESClient.Info()
		if err != nil {
			Critical("Problem interacting with elastic" + err.Error())
		}
		slog.Info("Elasticsearch Info", "info", i)
		Logger.ESLogLevel = LogLevel(config.ElasticLevel)
		// set default logger
		slog.SetDefault(slog.New(NewLogHandler(true, config.AddSource)))
	} else {
		// use os.StdOut
		slog.SetDefault(slog.New(NewLogHandler(false, config.AddSource)))
	}
}

// nolint: revive
func Critical(msg string, args ...any) {
	slog.Log(context.Background(), LevelCritical, msg, args...)
}

// nolint: revive
func LogLevel(l string) slog.Level {
	switch strings.ToUpper(l) {
	case "TRACE":
		return LevelTrace
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "NOTICE":
		return LevelNotice
	case "WARNING":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	case "CRITICAL":
		return LevelCritical
	default:
		return slog.LevelInfo
	}
}