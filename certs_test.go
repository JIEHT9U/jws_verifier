package googleauthidtokenverifier

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const testCerts = `{
  "keys": [
    {
      "kid": "cb404383844b46312769bb929ecec57d0ad8e3bb",
      "e": "AQAB",
      "kty": "RSA",
      "alg": "RS256",
      "n": "uqDFOtHWFjG-G8cHq4O8zZvOXzbXFBRaM05IGxigCJj6sSe5K0YG30ygPTDoQXaa1uzSWqt2vS4Cs13Uta_5Qr3une0wqkFmIVw6Xeb60JnsV10bR7ZzOC_gnQFvLyTH8zHwb-oCVUrI8ExWhI1YT_txq3w9ROvAylSGcsadZOEobb1HPsRoelRTOKqyCVhJEJL6sxDq1vFYtASMoB2qzk7AR-Uf2Smbg8al-9ljgwYmi7V7z16AQ8c713E9QPfrJzoPYPIofzAulf5LvZxaa-tTLDJstPpoJbLesgI8rNF9fVRzUJ4J6ivo3tJp9PUVWPoW0e5VK8fPWSfOrF6ENw",
      "use": "sig"
    },
    {
      "use": "sig",
      "kid": "a541d6ef022d77a2318f7dd657f27793203bed4a",
      "e": "AQAB",
      "kty": "RSA",
      "alg": "RS256",
      "n": "lKEwSQCvcQcoq3fG1QPi9fnAHF-wmn1Q4j_JtViQ94dlYSQ7TRxr2RrzxVIPpVZ_S6mZETOn_VzX7jhHXRbyXBiITTcpuv8vIDvCDY4NpOFQxhM6sfuAMH5HJJNgtmm_t59qxucMgVcz1y4WNnQqMOs-kVPh8T74oC_bRZ5u2yCSO9olktaeizQ5lMRGB80epzfllibPK62DfxWy8Z7o4MqMq5b1veE7Z6Dij2mwY_nHsx4B1YpwD67ntjn0G1I7wqG3Z5xRJOzXRnGwGRu0wTiQgwplgG3Nbme2sPnbmQ7apG1BBvAcOLC7D2J3pf6JtcD7vJS3SOnsGTmhFz2P-Q"
    }
  ]
}`

func googleMock(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("cache-control", "max-age=7500")
		w.WriteHeader(200)
		_, err := w.Write([]byte(testCerts))
		assert.NoError(t, err)
	}))
}

func TestGetFederatedSignonCerts(t *testing.T) {
	var google = googleMock(t)
	defer google.Close()

	var verifier = New().SetGoogleOAuth2FederatedSignorCertsURL(google.URL)
	assert.NoError(t, verifier.checkFederatedSignonCerts())

	var certs, err = verifier.GetCerts()
	assert.NoError(t, err)

	var cacheAge = certs.Expiry.Sub(time.Now()).Seconds()
	assert.Greater(t, cacheAge, float64(7400))
	assert.Less(t, cacheAge, float64(7500))

	key, err := verifier.certs.getKey("a541d6ef022d77a2318f7dd657f27793203bed4a")
	assert.NoError(t, err)
	assert.NotNil(t, key)

	key, err = verifier.certs.getKey("cb404383844b46312769bb929ecec57d0ad8e3bb")
	assert.NoError(t, err)
	assert.NotNil(t, key)
}
