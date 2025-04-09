package nvda_remote_go

import (
	"log/slog"

	"github.com/denizsincar29/nvda_remote_go/fingerprints"
)

type ClientBuilder struct {
	Host    string
	Port    string
	Channel string
	ConType string
	Logger  *slog.Logger
	fpc     *fingerprints.Config
}

func NewClientBuilder() *ClientBuilder {
	return &ClientBuilder{
		Host:    "nvdaremote.com",
		Port:    DEFAULT_PORT,
		Channel: "nvda",
		ConType: "master",
		Logger:  slog.Default(),
		fpc:     &fingerprints.Config{},
	}
}

func (cb *ClientBuilder) WithHost(host string) *ClientBuilder {
	cb.Host = host
	return cb
}

func (cb *ClientBuilder) WithPort(port string) *ClientBuilder {
	cb.Port = port
	return cb
}

func (cb *ClientBuilder) WithChannel(channel string) *ClientBuilder {
	cb.Channel = channel
	return cb
}

func (cb *ClientBuilder) AsMaster() *ClientBuilder {
	cb.ConType = "master"
	return cb
}

func (cb *ClientBuilder) AsSlave() *ClientBuilder {
	cb.ConType = "slave"
	return cb
}

func (cb *ClientBuilder) WithLogger(logger *slog.Logger) *ClientBuilder {
	cb.Logger = logger
	return cb
}

func (cb *ClientBuilder) WithFingerprintManagerAppName(appName string) *ClientBuilder {
	cb.fpc.AppName = appName
	return cb
}

func (cb *ClientBuilder) WithFingerprintManagerDirectory(dir string) *ClientBuilder {
	cb.fpc.Directory = dir
	return cb
}

func (cb *ClientBuilder) Build() (*NVDARemoteClient, error) {
	fm, err := fingerprints.NewFingerprintManager(*cb.fpc)
	if err != nil {
		return nil, err
	}
	return NewClient(cb.Host, cb.Port, cb.Channel, cb.ConType, cb.Logger, fm)
}
