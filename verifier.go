package jwsverifier

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"
	"time"
)

type Verifier struct {
	maxTokenLifetime                    time.Duration
	clockSkew                           time.Duration
	issuers                             []string
	googleOAuth2FederatedSignorCertsURL string
	certs                               *certs
}

type certs struct {
	mx    sync.RWMutex
	certs Certs
}

func (c *certs) set(certs Certs) {
	c.mx.Lock()
	c.certs = certs
	c.mx.Unlock()
}

func (c *certs) get() (certs Certs, exist bool) {
	c.mx.RLock()
	defer c.mx.RUnlock()
	if c == nil {
		return certs, false
	}
	return c.certs, true
}

func (c *certs) getKey(keyID string) (*rsa.PublicKey, error) {
	certs, exist := c.get()
	if !exist {
		return nil, ErrPublicKeyNotFound
	}
	if key, found := certs.Keys[keyID]; found {
		return key, nil
	}
	return nil, ErrPublicKeyNotFound
}

func New() *Verifier {
	return &Verifier{
		maxTokenLifetime:                    time.Second * 86400,
		clockSkew:                           time.Minute * 5,
		googleOAuth2FederatedSignorCertsURL: "https://www.googleapis.com/oauth2/v3/certs",
		issuers: []string{
			"accounts.google.com",
			"https://accounts.google.com",
		},
		certs: new(certs),
	}
}

func (v *Verifier) GetCerts() (certs Certs, err error) {
	if certs, exist := v.certs.get(); exist {
		return certs, nil
	}
	return certs, errors.New("error certs doesn't exist")
}

func (v *Verifier) SetMaxTokenLifetime(maxTokenLifetime time.Duration) *Verifier {
	v.maxTokenLifetime = maxTokenLifetime
	return v
}

func (v *Verifier) SetClockSkew(clockSkew time.Duration) *Verifier {
	v.clockSkew = clockSkew
	return v
}

func (v *Verifier) SetGoogleOAuth2FederatedSignorCertsURL(url string) *Verifier {
	v.googleOAuth2FederatedSignorCertsURL = url
	return v
}

func (v *Verifier) SetIssuers(issuers []string) *Verifier {
	v.issuers = issuers
	return v
}

func (v *Verifier) VerifyIDToken(idToken string, audience []string) error {
	return checkFederatedSignonCerts(v, func(verifier *Verifier) error {
		return verifier.verifySignedJWTWithCerts(idToken, audience)
	})
}

func checkFederatedSignonCerts(v *Verifier, f func(verifier *Verifier) error) error {
	if err := v.checkFederatedSignonCerts(); err != nil {
		return fmt.Errorf("error get federated signon certs err_msg=%w", err)
	}
	return f(v)
}
