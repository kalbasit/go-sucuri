package sucuri

// ScanResult represents the result of the Scan command of a host
type ScanResult struct {
	// Blacklist represents a blacklist response
	Blacklist struct {
		Info   [][]string `json:"INFO,omitempty"`
		Warn   [][]string `json:"WARN,omitempty"`
		Notice [][]string `json:"NOTICE,omitempty"`
		Error  [][]string `json:"ERROR,omitempty"`
	} `json:"BLACKLIST,omitempty"`

	// Links represents a links response
	Links struct {
		JSExternal []string `json:"JSEXTERNAL,omitempty"`
		JSLocal    []string `json:"JSLOCAL,omitempty"`
		URL        []string `json:"URL,omitempty"`
	} `json:"LINKS,omitempty"`

	// Recommendations represents a list of recommendations
	Recommendations [][]string

	// Malware represents a malware response
	Malware struct {
		Info   [][]string `json:"INFO,omitempty"`
		Warn   [][]string `json:"WARN,omitempty"`
		Notice [][]string `json:"NOTICE,omitempty"`
		Error  [][]string `json:"ERROR,omitempty"`
	} `json:"MALWARE,omitempty"`

	// Scan represents a scan response
	Scan struct {
		Domain []string `json:"DOMAIN,omitempty"`
		IP     []string `json:"IP,omitempty"`
		Site   []string `json:"SITE,omitempty"`
	} `json:"SCAN,omitempty"`

	// System represents a system response
	System struct {
		Info   []string `json:"INFO,omitempty"`
		Warn   []string `json:"WARN,omitempty"`
		Notice []string `json:"NOTICE,omitempty"`
		Error  []string `json:"ERROR,omitempty"`
	} `json:"SYSTEM,omitempty"`

	// Version represents a version response
	Version struct {
		BuildDate   []string `json:"BUILDDATE,omitempty"`
		CompiteDate []string `json:"COMPILEDDATE,omitempty"`
		DBDate      []string `json:"DBDATE,omitempty"`
		Version     []string `json:"VERSION,omitempty"`
	} `json:"VERSION,omitempty"`

	// WebApp represents a WebApp response
	WebApp struct {
		Info    [][]string `json:"INFO,omitempty"`
		Warn    [][]string `json:"WARN,omitempty"`
		Notice  [][]string `json:"NOTICE,omitempty"`
		Error   [][]string `json:"ERROR,omitempty"`
		Version []string   `json:"VERSION,omitempty"`
	} `json:"WEBAPP,omitempty"`
}
