package sucuri

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kalbasit/go-sucuri/testdata"
)

const key = "api_key"

func TestScan(t *testing.T) {
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

	t.Run("key is missing", func(t *testing.T) {
		_, err := NewClient(srv.URL, "")
		assert.EqualError(t, err, ErrKeyMissing.Error())
	})

	t.Run("baseURL is missing", func(t *testing.T) {
		_, err := NewClient("", key)
		assert.EqualError(t, err, ErrBaseURLMissing.Error())
	})

	t.Run("format is set", func(t *testing.T) {
		c, err := NewClient(srv.URL, key)
		if assert.NoError(t, err) {
			assert.Equal(t, "json", c.baseURL.Query().Get("format"))
		}
	})

	c, err := NewClient(srv.URL, key)
	require.NoError(t, err)

	t.Run("returns an error if the server returned a non 200 OK response", func(t *testing.T) {
		status = http.StatusNotFound
		defer func() { status = http.StatusOK }()

		_, err := c.Scan("google.com")
		assert.EqualError(t, err, "the API has returned: 404 Not Found Body: ")
	})

	t.Run("testdata/scan-google.com.json", func(t *testing.T) {
		res, err := c.Scan("google.com")
		require.NoError(t, err)

		if assert.NotNil(t, res) {
			// BLACKLIST -> INFO
			if assert.Len(t, res.Blacklist.Info, 9) {
				assert.Equal(t, []string{
					"Domain clean by Google Safe Browsing: google.com",
					"http://safebrowsing.clients.google.com/safebrowsing/diagnostic?site=google.com",
				}, res.Blacklist.Info[0])

				assert.Equal(t, []string{
					"Domain clean by Norton Safe Web: google.com",
					"http://safeweb.norton.com/report/show?url=google.com",
				}, res.Blacklist.Info[1])

				assert.Equal(t, []string{
					"Domain clean on PhishTank: google.com",
					"http://www.phishtank.com/",
				}, res.Blacklist.Info[2])

				assert.Equal(t, []string{
					"Domain clean on the Opera browser: google.com",
					"http://opera.com/",
				}, res.Blacklist.Info[3])

				assert.Equal(t, []string{
					"Domain clean by SiteAdvisor: google.com",
					"http://www.siteadvisor.com/sites/google.com",
				}, res.Blacklist.Info[4])

				assert.Equal(t, []string{
					"Domain clean by the Sucuri Malware Labs: google.com",
					"http://labs.sucuri.net/?blacklist=google.com",
				}, res.Blacklist.Info[5])

				assert.Equal(t, []string{
					"Domain clean on SpamHaus DBL: google.com",
					"http://www.spamhaus.org/query/domain/google.com",
				}, res.Blacklist.Info[6])

				assert.Equal(t, []string{
					"Domain clean on Yandex (via Sophos): google.com",
					"http://www.yandex.com/infected?url=google.com&amp;l10n=en",
				}, res.Blacklist.Info[7])

				assert.Equal(t, []string{
					"Domain clean by ESET: google.com",
					"http://labs.sucuri.net/?eset",
				}, res.Blacklist.Info[8])
			}

			// LINKS
			assert.Equal(t, "/recaptcha/api.js", res.Links.JSLocal[0])
			assert.Equal(t, "/policies/terms/", res.Links.URL[0])

			// RECOMMENDATIONS
			if assert.Len(t, res.Recommendations, 1) && assert.Len(t, res.Recommendations[0], 3) {
				assert.Equal(t, "Security Header: X-Content-Type nosniff", res.Recommendations[0][0])
				assert.Equal(t, "We did not find the recommended security header to prevent Content Type sniffing on your site. ", res.Recommendations[0][1])
				assert.Equal(t, "http://kb.sucuri.net/warnings/hardening/headers-x-content-type", res.Recommendations[0][2])
			}

			// SCAN
			assert.Equal(t, "google.com", res.Scan.Domain[0])
			assert.Equal(t, "74.125.21.138", res.Scan.IP[0])
			assert.Equal(t, "http://google.com", res.Scan.Site[0])

			// SYSTEM
			assert.Equal(t, "Redirects to: http://ipv6.google.com/sorry/index?continue=http://google.com/&amp;q=EhAmADwCAAAAAPA8kf_-m8ysGJvmg9MFIhkA8aeDS5oeEl72p_I0abbJjGhRWpn_S-2RMgFy", res.System.Info[0])
			assert.Equal(t, "Running on: HTTP", res.System.Notice[0])

			// VERSION
			assert.Equal(t, "14 Dec 2017 16:56 UTC", res.Version.BuildDate[0])
			assert.Equal(t, "14 Dec 2017 21:56 UTC", res.Version.CompiteDate[0])
			assert.Equal(t, "11 Dec 2017 20:05 UTC", res.Version.DBDate[0])
			assert.Equal(t, "1.4", res.Version.Version[0])
		}
	})

	t.Run("testdata/scan-johnhackedsite.com.json", func(t *testing.T) {
		res, err := c.Scan("johnhackedsite.com")
		require.NoError(t, err)

		if assert.NotNil(t, res) {
			// BLACKLIST -> INFO
			if assert.Len(t, res.Blacklist.Info, 9) {
				assert.Equal(t, []string{
					"Domain clean by Google Safe Browsing: johnhackedsite.com",
					"http://safebrowsing.clients.google.com/safebrowsing/diagnostic?site=johnhackedsite.com",
				}, res.Blacklist.Info[0])

				assert.Equal(t, []string{
					"Domain clean by Norton Safe Web: johnhackedsite.com",
					"http://safeweb.norton.com/report/show?url=johnhackedsite.com",
				}, res.Blacklist.Info[1])

				assert.Equal(t, []string{
					"Domain clean on PhishTank: johnhackedsite.com",
					"http://www.phishtank.com/",
				}, res.Blacklist.Info[2])

				assert.Equal(t, []string{
					"Domain clean on the Opera browser: johnhackedsite.com",
					"http://opera.com/",
				}, res.Blacklist.Info[3])

				assert.Equal(t, []string{
					"Domain clean by SiteAdvisor: johnhackedsite.com",
					"http://www.siteadvisor.com/sites/johnhackedsite.com",
				}, res.Blacklist.Info[4])

				assert.Equal(t, []string{
					"Domain clean by the Sucuri Malware Labs: johnhackedsite.com",
					"http://labs.sucuri.net/?blacklist=johnhackedsite.com",
				}, res.Blacklist.Info[5])

				assert.Equal(t, []string{
					"Domain clean on SpamHaus DBL: johnhackedsite.com",
					"http://www.spamhaus.org/query/domain/johnhackedsite.com",
				}, res.Blacklist.Info[6])

				assert.Equal(t, []string{
					"Domain clean on Yandex (via Sophos): johnhackedsite.com",
					"http://www.yandex.com/infected?url=johnhackedsite.com&amp;l10n=en",
				}, res.Blacklist.Info[7])

				assert.Equal(t, []string{
					"Domain clean by ESET: johnhackedsite.com",
					"http://labs.sucuri.net/?eset",
				}, res.Blacklist.Info[8])
			}

			// LINKS -> JSEXTERNAL
			assert.Equal(t, "http://welcometotheglobalisnet.com/js.php?kk=25", res.Links.JSExternal[0])

			// LINKS -> JSLOCAL
			assert.Equal(t, "/wp-content/themes/twentythirteen/js/html5.js", res.Links.JSLocal[0])
			assert.Equal(t, "/wp-includes/js/jquery/jquery.js?ver=1.12.4", res.Links.JSLocal[1])
			assert.Equal(t, "/wp-includes/js/jquery/jquery-migrate.min.js?ver=1.4.1", res.Links.JSLocal[2])
			assert.Equal(t, "/wp-includes/js/imagesloaded.min.js?ver=3.2.0", res.Links.JSLocal[3])
			assert.Equal(t, "/wp-includes/js/masonry.min.js?ver=3.3.2", res.Links.JSLocal[4])
			assert.Equal(t, "/wp-includes/js/jquery/jquery.masonry.min.js?ver=3.1.2b", res.Links.JSLocal[5])
			assert.Equal(t, "/wp-content/themes/twentythirteen/js/functions.js?ver=20150330", res.Links.JSLocal[6])
			assert.Equal(t, "/wp-includes/js/wp-embed.min.js?ver=4.8.2", res.Links.JSLocal[7])

			// LINKS -> URL
			assert.Equal(t, "/", res.Links.URL[0])
			assert.Equal(t, "/2017/08/11/spend-money-on-investigate-reports-online-and-get/", res.Links.URL[1])
			assert.Equal(t, "/category/writers-tips/", res.Links.URL[2])
			assert.Equal(t, "/author/editor/", res.Links.URL[3])
			assert.Equal(t, "/2017/08/02/looking-to-find-imaginative-simply-writing/", res.Links.URL[4])
			assert.Equal(t, "/category/education-platform/", res.Links.URL[5])
			assert.Equal(t, "/2017/07/31/choose-custom-crafted-novel-comments-by-way-of-the/", res.Links.URL[6])
			assert.Equal(t, "/category/paper-writing/", res.Links.URL[7])
			assert.Equal(t, "/2017/07/21/elegant-report-outline-4/", res.Links.URL[8])
			assert.Equal(t, "/category/uncategorized/", res.Links.URL[9])
			assert.Equal(t, "/2017/07/20/specificity-of-article-writing-the-thesis/", res.Links.URL[10])
			assert.Equal(t, "/category/international-education/", res.Links.URL[11])
			assert.Equal(t, "/2017/07/18/americans-don-t-speak-english-7/", res.Links.URL[12])
			assert.Equal(t, "/2017/07/15/technical-implies-used-for-getting-and-checking/", res.Links.URL[13])
			assert.Equal(t, "/category/best-education/", res.Links.URL[14])
			assert.Equal(t, "/2017/07/13/seventeen-reasons-to-suspend-glyphosate-4/", res.Links.URL[15])
			assert.Equal(t, "/2017/07/13/classification-product-marketing-strategy/", res.Links.URL[16])
			assert.Equal(t, "/2017/07/12/nevertheless-anxious-regarding-your-dissertation/", res.Links.URL[17])
			assert.Equal(t, "/category/college-study-tours/", res.Links.URL[18])
			assert.Equal(t, "/page/2/", res.Links.URL[19])

			// MALWARE -> WARN
			if assert.Len(t, res.Malware.Warn, 3) {
				assert.Equal(t, []string{
					"Security warning in the URL: http://johnhackedsite.com/",
					"*Known Spam detected. Details: http://labs.sucuri.net/db/malware/spam-seo.spammy_keywords?19.16\n&lt;/script&gt; &lt;a href=&quot;http://atlantic-drugs.net/products/viagra.htm&quot;; target=&quot;_blank&quot;&gt;viagra&lt;/a&gt; &lt;/center&gt;\n",
				}, res.Malware.Warn[0])

				assert.Equal(t, []string{
					"Blacklisted javascript included on:  http://johnhackedsite.com",
					"*Javascript included from a blacklisted domain. Details: http://sucuri.net/malware/entry/MW:BLK:2\nJavascript: welcometotheglobalisnet.com",
				}, res.Malware.Warn[1])

				assert.Equal(t, []string{
					"Security warning in the URL (for Google's UA): http://johnhackedsite.com",
					"*Known Spam detected. Details: http://labs.sucuri.net/db/malware/spam-seo.spammy_keywords?19.16\n&lt;/script&gt; &lt;a href=&quot;http://atlantic-drugs.net/products/viagra.htm&quot;; target=&quot;_blank&quot;&gt;viagra&lt;/a&gt; &lt;/center&gt;\n",
				}, res.Malware.Warn[2])
			}

			// SCAN
			assert.Equal(t, "johnhackedsite.com", res.Scan.Domain[0])
			assert.Equal(t, "192.124.249.64", res.Scan.IP[0])
			assert.Equal(t, "http://johnhackedsite.com", res.Scan.Site[0])

			// SYSTEM -> NOTICE
			assert.Equal(t, []string{
				"Running on: nginx",
				"Running on: Sucuri/Firewall",
			}, res.System.Notice)

			// VERSION
			assert.Equal(t, "14 Dec 2017 16:56 UTC", res.Version.BuildDate[0])
			assert.Equal(t, "14 Dec 2017 21:56 UTC", res.Version.CompiteDate[0])
			assert.Equal(t, "11 Dec 2017 20:05 UTC", res.Version.DBDate[0])
			assert.Equal(t, "1.4", res.Version.Version[0])

			// WEBAPP
			assert.Equal(t, []string{
				"Application: WordPress 4.8.2",
				"http://www.wordpress.org",
			}, res.WebApp.Info[0])
			assert.Equal(t, "WordPress version:  4.8.2", res.WebApp.Version[0])
		}
	})
}
