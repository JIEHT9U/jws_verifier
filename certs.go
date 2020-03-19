package jwsverifier

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

type Certs struct {
	Keys   map[string]*rsa.PublicKey
	Expiry time.Time
}

type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"Kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func (v *Verifier) checkFederatedSignonCerts() error {
	if certs, exist := v.certs.get(); exist && !certs.isExpired() {
		return nil
	}

	res, cacheAge, err := getNewCerts(v.googleOAuth2FederatedSignorCertsURL)
	if err != nil {
		return err
	}

	publicKeys, err := encodingPublicKeys(res.Keys)
	if err != nil {
		return err
	}

	v.certs.set(Certs{
		Keys:   publicKeys,
		Expiry: time.Now().Add(time.Second * time.Duration(cacheAge)),
	})

	return nil
}

var re = regexp.MustCompile("max-age=([0-9]*)")

func (c Certs) isExpired() bool {
	if time.Now().Before(c.Expiry) {
		return false
	}
	return true
}

func getNewCerts(googleOAuth2FederatedSignorCertsURL string) (*JWKS, int64, error) {
	var resp, err = http.Get(googleOAuth2FederatedSignorCertsURL)
	if err != nil {
		return nil, 0, fmt.Errorf("error get federated signor certs err_msg=%w", err)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, 0, fmt.Errorf("error JWKS decode err_msg=%w", err)
	}

	cacheAge, err := getCacheAge(resp.Header.Get("cache-control"))
	if err != nil {
		return nil, 0, fmt.Errorf("error get cache age err_msg=%w", err)
	}

	return &jwks, cacheAge, nil
}

func getCacheAge(cacheControl string) (int64, error) {
	var cacheAge int64 = 7200
	if cacheControl == "" {
		return cacheAge, nil
	}

	var match = re.FindAllStringSubmatch(cacheControl, -1)
	if len(match) != 0 && len(match[0]) == 2 {
		return strconv.ParseInt(match[0][1], 10, 64)
	}
	return cacheAge, nil
}

func encodingPublicKeys(keys []JWK) (_ map[string]*rsa.PublicKey, err error) {
	var result = make(map[string]*rsa.PublicKey)
	for _, key := range keys {
		if key.Use == "sig" && key.Kty == "RSA" {
			if result[key.Kid], err = encodingKey(key); err != nil {
				return nil, err
			}
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("error encoding public JWK")
	}
	return result, nil
}

func encodingKey(k JWK) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	e, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{
		N: big.NewInt(0).SetBytes(n),
		E: int(big.NewInt(0).SetBytes(e).Int64()),
	}, nil
}
