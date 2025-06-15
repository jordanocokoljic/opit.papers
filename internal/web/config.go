package web

import "time"

type ServerConfiguration struct {
	SessionLifetime time.Duration
	ResetLifetime   time.Duration
}

func DefaultServerConfiguration() ServerConfiguration {
	return ServerConfiguration{
		SessionLifetime: time.Hour * 8,
		ResetLifetime:   time.Minute * 15,
	}
}
