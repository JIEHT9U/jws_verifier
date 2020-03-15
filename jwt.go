package jwsverifier

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// verifySignedJWTWithCerts is golang port of OAuth2Client.prototype.verifySignedJwtWithCerts
func (v *Verifier) verifySignedJWTWithCerts(token string, allowedAuds []string) error {
	var header, claimSet, err = parseJWT(token)
	if err != nil {
		return err
	}

	key, err := v.certs.getKey(header.KeyID)
	if err != nil {
		return err
	}
	if err := Verify(token, key); err != nil {
		return ErrWrongSignature
	}
	if claimSet.Iat < 1 {
		return ErrNoIssueTimeInToken
	}
	if claimSet.Exp < 1 {
		return ErrNoExpirationTimeInToken
	}
	var now = time.Now()
	if claimSet.Exp > now.Unix()+int64(v.maxTokenLifetime.Seconds()) {
		return ErrExpirationTimeTooFarInFuture
	}

	earliest := claimSet.Iat - int64(v.clockSkew.Seconds())
	latest := claimSet.Exp + int64(v.clockSkew.Seconds())

	if now.Unix() < earliest {
		return ErrTokenUsedTooEarly
	}

	if now.Unix() > latest {
		return ErrTokenUsedTooLate
	}

	found := false
	for _, issuer := range v.issuers {
		if issuer == claimSet.Iss {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("Wrong issuer: %s", claimSet.Iss)
	}

	audFound := false
	for _, aud := range allowedAuds {
		if aud == claimSet.Aud {
			audFound = true
			break
		}
	}
	if !audFound {
		return fmt.Errorf("Wrong aud: %s", claimSet.Aud)
	}

	return nil
}

func parseJWT(token string) (*Header, *ClaimSet, error) {
	s := strings.Split(token, ".")
	if len(s) != 3 {
		return nil, nil, errors.New("Invalid token received")
	}
	decodedHeader, err := base64.RawURLEncoding.DecodeString(s[0])
	if err != nil {
		return nil, nil, err
	}
	var header Header
	err = json.NewDecoder(bytes.NewBuffer(decodedHeader)).Decode(&header)
	if err != nil {
		return nil, nil, err
	}
	var claimSet ClaimSet
	if err := Decode(token, &claimSet); err != nil {
		return nil, nil, err
	}
	return &header, &claimSet, nil
}

//// Decode returns ClaimSet
//func Decode(token string) (*ClaimSet, error) {
//	s := strings.Split(token, ".")
//	if len(s) != 3 {
//		return nil, ErrInvalidToken
//	}
//	decoded, err := base64.RawURLEncoding.DecodeString(s[1])
//	if err != nil {
//		return nil, err
//	}
//	c := &ClaimSet{}
//	err = json.NewDecoder(bytes.NewBuffer(decoded)).Decode(c)
//	return c, err
//}
