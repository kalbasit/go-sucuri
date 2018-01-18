# Sucuri Golang client

[![godoc](http://img.shields.io/badge/godoc-reference-blue.svg?style=flat)](https://godoc.org/github.com/kalbasit/go-sucuri) [![license](http://img.shields.io/badge/license-MIT-red.svg?style=flat)](https://raw.githubusercontent.com/kalbasit/go-sucuri/master/LICENSE) [![Build Status](https://travis-ci.org/kalbasit/go-sucuri.svg?branch=master)](https://travis-ci.org/kalbasit/go-sucuri) [![Coverage](http://gocover.io/_badge/github.com/kalbasit/go-sucuri)](http://gocover.io/github.com/kalbasit/go-sucuri)

# Install

Install using the "go get" command:

```
go get github.com/kalbasit/go-sucuri
```

# Usage

Create a new instance given a base URL and an API key, and call `Scan`
with a given domain to get back the scan result.  You can find the base
URL and the API key on the dashboard of [your
account](https://login.sucuri.net/login/).

```go
// create a new client
c, err := sucuri.NewClient("https://monitorxx.sucuri.net", "3ba516ef0db31f7c1b788864cb0adf10b5cc0db5e810c708c4")
if err != nil {
  log.Fatalf("error creating a new API client: %s", err)
}
// scan mydomain.com
sr, err := c.Scan("mydomain.com")
if err != nil {
  log.Fatalf("error scanning mydomain.com: %s", err)
}
// ... use sr of type *sucuri.ScanResult
```

# License

All source code is licensed under the [MIT License](LICENSE).
