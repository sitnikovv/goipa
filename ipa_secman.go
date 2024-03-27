package ipa

import (
	"crypto/tls"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"net"
	"net/http"
	"time"
)

func newSecmanHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 1 * time.Minute,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{RootCAs: ipaCertPool},
			DisableCompression:    false,
		},
	}
}

// LoginWithConfig соединяется с FreeIPA используя локальный логин и пароль, с прямой передачей конфигурации
func (c *Client) LoginWithConfig(username, password string, cfg *config.Config) error {
	cl := client.NewWithPassword(username, c.realm, password, cfg)

	err := cl.Login()
	if err != nil {
		return err
	}

	c.krbClient = cl

	return nil
}

// LoginWithKeytabAndConfig соединяется с FreeIPA используя локальный логин, с прямой передачей keytab и конфигурации
func (c *Client) LoginWithKeytabAndConfig(username string, kt *keytab.Keytab, cfg *config.Config) error {
	cl := client.NewWithKeytab(username, c.realm, kt, cfg)

	err := cl.Login()
	if err != nil {
		return err
	}

	c.krbClient = cl

	return nil
}

// LoginFromCCacheWithConfig соединяется с FreeIPA используя аутентификационные данные из файлового кеша, с прямой передачей этого кэша и конфигурации
func (c *Client) LoginFromCCacheWithConfig(ccache *credentials.CCache, cfg *config.Config) error {
	cl, err := client.NewFromCCache(ccache, cfg, client.AssumePreAuthentication(true))
	if err != nil {
		return err
	}

	err = cl.Login()
	if err != nil {
		return err
	}

	c.krbClient = cl

	return nil
}

// LoginWithClient соединяется с FreeIPA используя переданный kerberos клиент
func (c *Client) LoginWithClient(cl *client.Client) error {
	err := cl.Login()
	if err != nil {
		return err
	}

	c.krbClient = cl

	return nil
}

// SetClient устанавливает kerberos клиент
func (c *Client) SetClient(cl *client.Client) {
	c.krbClient = cl
}

// WhoAmI Получает информацию о текущем пользователе
func (c *Client) WhoAmI() (string, error) {

	res, err := c.rpc("whoami/1", []string{}, Options{})

	if err != nil {
		return "", err
	}

	return res.Principal, nil
}
