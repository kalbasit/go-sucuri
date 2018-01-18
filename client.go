package sucuri

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

var (
	// ErrKeyMissing is returned if the key is empty
	ErrKeyMissing = errors.New("key must not be empty")

	// ErrBaseURLMissing is returned if the base URL is empty
	ErrBaseURLMissing = errors.New("base URL is missing")

	httpClient = http.DefaultClient
	jsonFormat = "json"
	scanAction = "scan"
	scanPath   = "/scan-api.php"
)

// Client represents a Sucuri client
type Client struct{ baseURL *url.URL }

// NewClient returns a new client configured
func NewClient(baseURL string, key string) (*Client, error) {
	if baseURL == "" {
		return nil, ErrBaseURLMissing
	}
	if key == "" {
		return nil, ErrKeyMissing
	}
	// parse the url
	bup, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	// add the key to the base URL
	q := bup.Query()
	q.Set("k", key)
	q.Set("format", jsonFormat)
	bup.RawQuery = q.Encode()

	return &Client{baseURL: bup}, nil
}

// Scan scans the domain and returns the scan result
func (c *Client) Scan(domain string) (*ScanResult, error) {
	var (
		uri = &url.URL{}
		q   url.Values
		r   *http.Request
		res *http.Response
		err error
		sr  ScanResult
	)

	// duplicate the base URL
	*uri = *c.baseURL
	// add the path
	uri.Path = scanPath
	// add the action and the host to it
	q = uri.Query()
	q.Set("a", scanAction)
	q.Set("host", domain)
	uri.RawQuery = q.Encode()
	// create the request
	r, err = http.NewRequest("GET", uri.String(), nil)
	if err != nil {
		return nil, err
	}
	// do the actual request
	res, err = httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		// read the entire body
		var b []byte
		b, err = ioutil.ReadAll(res.Body)
		if err != nil {
			b = []byte{}
		}
		return nil, fmt.Errorf("the API has returned: " + res.Status + " Body: " + string(b))
	}
	// parse the body
	if err = json.NewDecoder(res.Body).Decode(&sr); err != nil {
		return nil, err
	}

	return &sr, nil
}
