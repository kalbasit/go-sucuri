package sucuri

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kalbasit/go-sucuri/testdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlacklisted(t *testing.T) {
	status := http.StatusOK
	// create the test server that will emulate the Sucuri API
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// check the required parameters
		if r.URL.Query().Get("k") != key {
			http.Error(w, "the key is missing or invalid", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("a") != "scan" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("host") == "" {
			http.Error(w, "host is missing", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("format") != "json" {
			http.Error(w, fmt.Sprintf("format is set to %q, must be set to %q", r.URL.Query().Get("format"), jsonFormat), http.StatusBadRequest)
			return
		}
		if r.URL.Path != scanPath {
			http.Error(w, fmt.Sprintf("path is set to %q, must be set to %q", r.URL.Path, scanPath), http.StatusBadRequest)
			return
		}
		if status == http.StatusOK {
			// fetch the asset from testdata
			assetPath := fmt.Sprintf("testdata/scan-%s.json", r.URL.Query().Get("host"))
			response, err := testdata.Asset(assetPath)
			if err != nil {
				http.Error(w, fmt.Sprintf("error fetching the asset %q from the testdata: %s", assetPath, err), http.StatusNotFound)
				return
			}
			w.Write([]byte(response))
		} else {
			w.WriteHeader(status)
		}
	}))
	defer srv.Close()

	// replace the client
	oldHTTPClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldHTTPClient }()

	c, err := NewClient(srv.URL, key)
	require.NoError(t, err)

	t.Run("testdata/scan-google.com.json", func(t *testing.T) {
		res, err := c.Scan("google.com")
		require.NoError(t, err)
		assert.False(t, res.Blacklisted())
	})

	t.Run("testdata/scan-johnhackedsite.com.json", func(t *testing.T) {
		res, err := c.Scan("johnhackedsite.com")
		require.NoError(t, err)
		assert.True(t, res.Blacklisted())
	})

	t.Run("testdata/scan-trafficconverter.biz.json", func(t *testing.T) {
		res, err := c.Scan("trafficconverter.biz")
		require.NoError(t, err)
		assert.True(t, res.Blacklisted())
	})
}
