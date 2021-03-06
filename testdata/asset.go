// Code generated by go-bindata.
// sources:
// testdata/scan-johnhackedsite.com.json
// testdata/scan-google.com.json
// testdata/scan-trafficconverter.biz.json
// DO NOT EDIT!

package testdata

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _testdataScanJohnhackedsiteComJson = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xec\x58\xef\x6f\xdb\x38\x12\xfd\xde\xbf\x82\xc8\x87\xde\xee\x61\x29\x5a\x8a\xd3\x1f\x0e\x82\xc0\x49\xbc\x77\x6e\x9d\x1f\x88\x93\xcb\x2d\xae\x87\x05\x4d\x8d\x25\xc6\x14\xa9\x25\x47\x56\x75\x87\xfe\xef\x07\x4a\x4e\x62\xc7\x96\x5b\x37\xbd\x6f\x5b\xa0\x88\xad\x70\xde\xbc\x79\x7c\xd4\x0c\xf3\xdf\x57\x84\x10\xb2\x77\x32\xea\x9f\x7e\x1c\x0d\xc7\x37\x7b\x3d\xd2\x3c\xaa\x1f\x0f\x2f\x7e\xbd\xdc\xeb\x91\x7f\x3d\x3e\xf1\xff\x56\xbf\xd5\xeb\xce\x4c\xc6\xa5\x26\x42\x01\xd7\x64\x52\x91\xbf\x19\x93\x28\x20\x63\x3e\x05\x72\x62\x4d\xe9\xa4\x4e\x7a\xe4\xde\xa4\x3a\xe5\x62\x06\xb1\x93\x08\x81\x30\xd9\xde\x2f\xeb\x58\x29\x62\xde\x63\xcc\xf1\x29\x4c\x16\xa1\x81\x50\x12\x34\xba\x20\xa9\x71\x7d\xe4\xca\xef\x59\x2c\x79\xa2\x8d\x43\x29\x8e\x3d\xf4\xd1\x86\x4c\x2b\x89\xfe\xfd\xcb\xae\x15\x5d\x18\x8b\x46\x37\x15\xdd\xc1\xe4\x3b\x8a\x29\x61\x12\xe8\x1a\xa5\xe6\x6f\x21\x37\x16\x99\x4b\x4d\x79\x5c\x58\xf5\xa3\x29\x1b\x4d\xae\x52\xe9\xd2\x1b\xae\x67\x3b\x92\x2d\xcb\x32\xc8\x7d\x2c\x72\x3d\xab\xb9\xbe\x94\x09\xa6\x40\x2e\x73\xb0\x9c\xd4\x3b\x06\x76\x47\x46\xc6\xc7\xbe\x9c\xc9\xa4\x22\x63\x89\xd0\x8f\xe7\xd2\x99\x5d\x39\x78\x55\xfc\x32\xde\x44\x37\x1e\x94\x08\x8e\xfd\x78\xb3\x79\xbd\xc6\x85\x28\xac\x24\xe7\x5c\x95\xdc\x02\x19\xf1\x89\xdb\x91\xb1\xe2\x13\x17\xb8\x1a\x26\xd0\x80\xec\x78\xa2\xb8\x98\x29\xe9\xf0\xff\x60\xb6\x71\xce\xb3\xbf\xf3\xc2\x91\xb3\x93\xd1\xf7\x28\x9b\xf3\x2c\xe5\x85\x0b\x8c\x4d\xd8\x1f\x05\xd8\x8a\xc5\x75\x86\x1f\xad\xae\xd1\xe4\x37\xae\x63\xf8\x4c\x7e\x9a\x4b\x4e\xc6\x26\x4f\x8d\xfb\xf9\x3b\x18\x57\x35\x4a\x6d\x03\xa9\xa7\x20\x10\xe2\x96\x73\xfc\x9a\x67\xf9\xa1\x0a\x3b\xfa\x08\xf4\x4b\x9d\x31\x18\x0f\x6e\x5e\x6a\x03\x70\x80\xcf\x78\xbc\x5a\xfd\xf4\xa5\x41\xdb\x1b\x0d\x2f\x3e\x8e\x57\x3b\xc2\x87\xf1\xe0\x9f\x37\x83\xeb\x8b\xfe\x68\xad\x2f\x3c\xaa\x03\x4a\x98\x0c\xd0\x60\x0a\x89\x32\x13\xae\xa4\xd3\x80\xb5\x54\xf7\x2e\xc8\xd3\xfc\x78\x36\x3b\x8a\x0e\x9e\x38\x2c\xe9\xb0\xf7\x61\x3c\xba\x3c\xdd\x84\xce\xca\x9c\x0a\xa3\x11\x34\x32\x4c\x21\x03\xc7\xb0\x04\x8d\x15\xa6\xd2\x22\x80\x66\xf7\x8e\xa5\x98\xa9\x83\xe0\xde\x3d\xd3\xa3\x0e\x96\x5a\xa8\x22\xf6\x07\xd6\xb1\xfb\xc6\x63\xcd\x8f\xe0\xde\x1d\xcf\xc1\x1e\x85\x41\x18\x05\xdd\x9d\x42\x69\x26\x13\xcb\x11\x82\x4c\xea\x27\x98\x6e\x10\x7e\x0d\x45\x66\x3c\x01\xa7\x0c\x8f\x21\x5e\x0e\xde\x0f\xa2\xa0\xf3\xb5\xe0\x8c\x3b\xa3\x6d\xb5\x1a\xb7\x1f\x44\xbb\x55\xbd\x11\x25\x0c\xa2\xc9\x26\x98\xaf\x2a\x3f\x2d\xb4\x40\x69\xb4\x7b\xc0\x8a\x3a\xe1\x41\x67\x7f\xff\xab\xc5\x94\x39\x85\x6c\xb2\xaa\x42\x37\x78\x17\x44\x9b\xfd\x71\x7b\xbd\xc9\x1b\x6b\x49\xa2\x4e\xf8\x96\x75\xde\xb1\x30\x64\x2e\x07\x1d\xd3\xcc\x68\xa8\xa8\xd1\x54\xea\x39\x38\x94\x09\x47\xa0\x4d\x13\x76\xd4\x68\x25\x35\x50\xae\x63\x9a\x00\xae\xa3\x09\x8e\x90\x18\x5b\xb1\xd2\x4a\x04\xeb\x28\xca\xdc\xad\x2f\xe3\x05\xa6\xc6\x32\x88\x25\x1a\xdb\xce\xa9\x13\x31\x65\xcc\x4c\xea\x84\xa2\xa1\x53\xa9\x63\xea\xed\x20\x35\x47\x39\x07\xea\x64\x96\xab\x8a\xfa\x54\x7e\xb6\x69\x27\x03\x71\x21\xb8\xd7\x9c\xe6\x8a\xe3\xd4\xd8\xac\x2d\xe7\x5b\xb6\x1f\x32\x91\x1a\xe3\x80\x8a\xc2\xa1\xc9\xa8\xb0\x7c\x8a\x10\x53\x6d\xe6\xa0\xa8\x30\x59\xe6\x27\x2c\x3a\xa9\x68\xc9\x2b\x6a\xa6\x14\x53\xd8\x92\x3b\xe7\x39\xd8\x76\x8e\x0f\x69\xa3\x90\x81\x82\x84\x6b\x5c\x68\x4d\x4d\x81\xb5\xd6\xdd\x2d\xe0\x85\x5e\x7c\x94\xff\x81\x78\x0b\x78\xc7\xef\xad\x90\x53\x29\x24\xd6\x9c\xb9\x45\x29\x14\x3c\xf0\xf2\x35\xf8\xff\x4e\x6e\xd8\xac\xc7\x6c\x52\x23\x58\x5d\x0b\xc9\x15\x7d\x14\xb5\x3d\x6f\xf8\x8e\xf1\x0c\xac\x14\x5c\x3b\x1a\x1b\x4d\x91\xba\x1c\xf8\x8c\x82\x4e\x94\x74\x29\x7d\xbb\x25\xf6\x80\x21\x88\x54\x4b\xc1\x15\xf5\x1b\x2d\xc1\xd1\xc2\x41\x4c\xa7\xc6\x7a\xf3\xd5\xbc\xbd\x11\x45\x0a\x62\xb6\xdd\x00\x13\x70\xf8\x4d\x84\xf7\x99\x83\x39\x68\x7f\x56\xa9\x05\x7f\xee\x9d\xb7\x9e\x2b\x9a\xb3\x91\xa8\xca\xb7\x41\x7f\x22\x36\x6c\xcb\x12\x8a\x50\xdc\x39\xaf\xf7\xc2\x76\xd6\xc4\x85\x40\x9a\x71\x3b\x83\x9a\xb8\x43\xff\x36\x4c\xaa\x2d\x28\x11\xd3\x30\x07\x8b\x29\x28\x70\x8e\x72\xfd\x59\x9a\xc2\x51\x0b\x09\xb7\xb1\xc7\xa8\x4c\x61\x69\x2c\x9d\x03\x8b\x2d\x85\x3d\x2a\x20\x8c\x52\x90\x00\x75\x58\xc4\x15\x45\x53\xd8\x0d\x3b\x9d\xf3\x04\x58\xb4\x34\x3b\xae\x76\xb9\xf3\xfe\xe8\xae\x7f\x3d\x58\xed\x73\x77\xfd\xeb\x8b\x6f\xb9\xf9\x8c\xc1\x37\x56\xac\x48\xc9\xad\x96\x3a\x21\xb2\x19\x77\x6f\xaf\x47\x3d\xb2\x68\x88\xeb\xed\xfa\x39\xc7\x1a\xea\xaf\x1f\xb5\x29\x9b\x49\x8a\xc4\x80\xf5\x48\x11\x90\x33\x40\x2e\x95\x7b\x04\x7b\xde\xce\xe3\x09\xcb\x9a\x19\x91\xf9\x21\x8a\x3a\x30\xf5\x34\x95\x55\xbf\xcf\xa0\x2a\x8d\x8d\xdd\x71\xf8\x3e\x08\xdf\x7c\xd2\xaf\x15\x1e\x32\x27\xac\xcc\xf1\x75\x82\x87\xc4\x7f\xe7\x24\xb5\x30\x3d\x7a\xfd\x47\x61\xf0\x70\x91\x82\xa3\xe2\x1a\xa5\xa0\xb1\x2d\x12\x57\x67\x59\xec\xb4\x63\x73\xc9\x13\xcb\x83\x14\xb3\x26\xe4\x90\x20\xb7\x09\xe0\x02\xe1\xf7\x89\xe2\x7a\xd6\x7c\xf6\x39\x9a\xe5\x75\x62\xfe\x98\x93\x09\x6f\x45\xeb\xbf\x7f\xda\x79\x22\x3a\x79\x18\x62\x21\x26\xf7\x7c\xce\x9b\x7a\xc8\xa2\xa3\xc4\xc4\xe8\x1e\x69\x17\x7e\xa3\xee\x1f\x36\xc0\x4c\xad\xc9\x08\x27\x93\xa5\x6c\xcd\x40\xba\xbe\x23\x4b\x9b\xf1\xb0\x13\xa0\xd1\x56\xec\xfc\xae\x77\x32\xfa\xd8\x8b\x3e\xe9\xa7\x0c\x3d\xb2\x65\x3c\xda\x55\x8b\x2d\xe6\x23\x3f\x4d\x8d\x5d\xdc\xc3\xff\xe2\xc8\x6d\xff\xe7\x2d\x76\xfc\xd3\x8d\x2d\x6e\x6c\x79\x63\x8c\x4f\xfb\x17\xab\xaf\x8b\xb3\xcb\xf3\xfe\x70\xfd\x85\xb1\xb7\xed\xf6\xb2\x3c\xd5\x0c\xaf\xd6\x63\xc3\xf7\x51\x10\x46\xdd\x20\xea\xbe\x0f\xde\x74\x37\xc7\x8d\x87\x37\x83\xd6\x41\x7c\x6b\xf2\xd5\x82\x7e\x1b\xdf\x0c\xce\x57\x4b\xba\xb8\xbc\x19\x9e\x6e\x00\xbf\x2e\x74\xed\x35\x7f\xd0\x74\x22\xf5\xe7\xe7\xef\xdb\xe5\x05\xcd\x2d\x96\xfd\x2a\x2d\x94\x5c\xa9\xb6\xfc\xff\x18\x5c\x8f\x87\x97\xcf\x34\x3d\xb9\x1d\x8e\xce\xce\xfa\x9b\x0a\x0c\xbb\xe4\x0c\x04\xf1\x3d\x85\x84\x6f\x7a\x07\x6f\xc8\xed\xcd\xe9\x66\x85\x4e\x2f\xcf\xaf\x86\xa3\xc1\x37\x00\x45\xe1\x56\xa0\xb3\x93\x16\x88\x70\x09\xa2\xd3\xeb\x1c\xb4\x43\x3c\x95\xf9\x1c\x23\xe8\xb6\x49\x73\x37\x38\xe9\x5f\x5d\x7d\xdf\x9f\xe5\xfa\x79\xae\x16\xbd\xba\x47\xee\x8c\x8d\xaf\x2c\x38\x47\x9a\xe9\x7a\xfb\xf5\xd6\x1f\xd5\xdc\xaf\xf6\x37\xf2\xd6\x53\xf1\x2d\xb5\x3d\xe5\x9d\x83\x75\x35\x15\xf2\x7c\xbe\x6f\x2a\x7e\xf5\xe5\xd5\xff\x02\x00\x00\xff\xff\x66\xed\xa8\x51\x8f\x14\x00\x00")

func testdataScanJohnhackedsiteComJsonBytes() ([]byte, error) {
	return bindataRead(
		_testdataScanJohnhackedsiteComJson,
		"testdata/scan-johnhackedsite.com.json",
	)
}

func testdataScanJohnhackedsiteComJson() (*asset, error) {
	bytes, err := testdataScanJohnhackedsiteComJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/scan-johnhackedsite.com.json", size: 5263, mode: os.FileMode(420), modTime: time.Unix(1516306424, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataScanGoogleComJson = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x56\x5d\x6f\xe2\x46\x14\x7d\xcf\xaf\xb8\xf2\x43\xd5\x4a\x8b\x0d\x34\x5f\xa5\x8a\x22\x83\x9d\xc4\x59\xbe\xc4\x38\x4d\x57\x55\x15\x8d\xed\x0b\x9e\xc5\x9e\xf1\xce\x8c\xf1\x5a\x55\xfe\x7b\x65\x43\x1b\x0c\xa4\x22\x4d\xfc\xe4\x4c\x38\xe7\x9e\x7b\xce\xbd\x03\x7f\x9d\x00\x00\x18\xfd\xa1\x3d\xf8\x3c\xf4\x88\x6f\xf4\x60\x7d\x54\x1f\x7b\xe3\x9b\x89\xd1\x83\x3f\xfe\x3d\xa9\x9e\xe6\x5f\xf5\xe7\x1c\x91\x52\xc6\x21\x4c\x90\x72\x08\x4a\xb8\x15\x62\x91\x20\x10\x3a\x47\xe8\x4b\x51\x28\xc6\x17\x3d\x58\xd4\xa7\x66\x28\x52\xe3\xd3\x3e\x47\xac\x75\xd6\xb3\x2c\x45\xe7\x18\x6c\x20\x66\x98\x30\xe4\x5a\x99\x2f\xc8\xc6\xff\xad\x88\xd1\x05\x17\x4a\xb3\xf0\x5a\x31\x8d\x57\x5b\x15\x1a\x05\xfe\xfc\xf4\xd6\x0e\xc6\x42\x6a\xc1\xd7\x1d\x3c\x62\xf0\x06\xf1\x05\x06\x26\xaf\xd1\xb5\x5e\x89\x99\x90\xda\x52\xb1\x28\xae\x73\x99\x7c\x94\x44\xc1\x61\x1a\x33\x15\xfb\x94\x2f\x8f\x14\x57\x14\x85\x99\x55\x18\x4d\xf9\xb2\xd6\xf6\x5e\x05\x3a\x46\x98\x64\x28\x29\xd4\x89\xa0\x3c\x52\x89\xa8\x30\xef\x57\x10\x94\x40\x98\x46\x3b\x5a\x31\x25\x8e\xad\x5d\xb9\x50\xcd\x0a\x5d\xa3\xd6\x33\xc5\x34\x2a\xeb\xe3\x86\xa7\xf2\x85\xe4\x61\x2e\x19\x8c\x68\x52\x50\x89\x30\xa4\x81\x3a\x52\x61\x42\x03\x65\xaa\x1a\x6e\x72\xd4\xd6\x75\x90\xd0\x70\x99\x30\xa5\x3f\x70\x78\x48\x46\xd3\x3b\x9a\x2b\x70\xfa\xc3\xb7\x38\x97\xd1\x34\xa6\xb9\x32\x85\x5c\x58\xdf\x72\x94\xa5\x15\xd5\xcc\x1f\xe5\x9e\xe0\xf0\x85\xf2\x08\xbf\xc3\x8f\x2b\x46\x81\x88\x2c\x16\xea\xa7\x37\x28\x2c\x6b\x74\x1d\x2b\xe3\x73\x0c\x35\x46\x3b\x7b\xf7\x03\x4d\xb3\x5f\x93\x4e\x9b\x5f\x21\x7f\x6f\xd2\x2e\x71\xfd\xff\x1b\x2b\x2a\xd4\x3b\xf5\x4f\x9a\x6f\xcf\x6b\x36\x63\xe8\x8d\x3f\x93\xe6\xcd\x7c\x4f\x86\x93\x81\x3d\xdc\xbb\x9c\x0d\x4b\x62\x48\x33\x1d\xc6\xd4\xa2\x19\x33\xbf\xaa\x97\x12\x5b\xed\x19\x0f\xb3\x43\xd8\x4c\x24\x2c\x64\xa8\x2c\x8d\x32\x55\x5b\xdb\xd9\xd4\x33\x73\x07\x93\xd1\xc8\x1d\x3b\xb6\xef\x4d\xc6\xa4\x41\xb4\x43\x49\xb0\x6a\x58\x97\x70\x87\x34\xaa\x2e\x88\xdf\x5b\x03\xc1\x35\x72\xdd\xf2\xcb\x0c\x81\x0b\xc5\xd9\x7c\xbe\xe3\x9b\xf1\x88\x10\xb1\x08\xb8\xd0\x30\x67\x3c\xaa\x37\x4a\x62\x28\xd2\x14\x79\x84\x11\xa8\x7f\x68\xe3\x9a\x16\xb4\x80\x4c\xe2\x0a\xb9\x86\x0d\x3d\xd4\xf4\x35\x39\xe3\x8b\x6a\xae\x4a\x91\x4b\xa8\x56\xdd\x84\xdd\x72\x9b\x88\x96\xc1\x76\x40\x05\x95\x9c\xf1\x85\xb2\x62\x2a\x23\xac\x5e\xad\x75\x35\xd5\xfa\xde\x0a\x37\x4d\xe8\x32\xc3\x5d\x9b\x36\x3e\x1b\x64\x60\x8f\x9b\xa9\x39\x93\x91\xed\x8d\xf7\x8d\x3f\xb4\x3c\xdb\x69\x79\xd3\x7d\xcc\xc5\xa9\xd9\xe9\x9e\x99\xdd\x8e\xd9\xf9\xf9\xf2\x30\x8c\x78\xbe\xbb\x0f\xdc\x34\x7b\xb0\x66\x23\x66\xf2\x85\xf8\xee\xe8\x88\x5f\x04\xc6\x0c\x23\x26\x31\xd4\x0a\xb4\xe8\xc1\xa6\x00\xcb\x56\xe7\x8d\x6f\x6e\x21\x65\x69\xb1\x6a\x3d\xaf\x2b\xfb\x18\xcf\xf1\x6a\x4f\x8c\x55\xaf\xe7\xb7\x2b\x37\xb6\x53\xdb\x29\x06\x76\xf5\x4c\xed\xcb\xe5\xfc\xa9\x95\x5e\x96\xea\xf6\x7e\x95\x2e\x7e\x19\xdd\x78\xf1\xd2\xbe\xa4\xe8\x90\x33\x81\x6e\x72\xd1\xcd\x9e\xbc\x36\x0d\x82\xfb\xaf\xb7\xf1\xec\x31\xe3\x4f\xa4\xd5\x9d\x8d\x16\x37\xe5\x61\x67\xc6\x13\xdf\x1b\x1c\xf0\x66\x96\x73\xbe\x1e\x97\x1e\xdc\xf9\xfe\xf4\x35\x6b\x7e\x73\x67\xc4\x9b\xec\xa4\xdb\x7f\xf0\x86\x8e\x63\x1f\xf2\xbc\x73\x0a\x0e\x86\xd0\x6d\x77\x2e\xa0\x73\xde\x3b\x3b\x87\x07\x7f\x70\x58\xda\x60\x32\x9a\x7a\x43\xf7\x08\xa2\x6e\xe7\x3f\x89\x9c\xfe\x2b\x14\x9d\x2d\x8a\x76\xaf\x7d\xf6\x3a\xc5\x4b\x9b\xbb\x1c\xe6\xe9\x9e\x35\x27\xcf\x27\x7f\x07\x00\x00\xff\xff\x9a\x3d\x69\x55\x4e\x0a\x00\x00")

func testdataScanGoogleComJsonBytes() ([]byte, error) {
	return bindataRead(
		_testdataScanGoogleComJson,
		"testdata/scan-google.com.json",
	)
}

func testdataScanGoogleComJson() (*asset, error) {
	bytes, err := testdataScanGoogleComJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/scan-google.com.json", size: 2638, mode: os.FileMode(420), modTime: time.Unix(1516306424, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataScanTrafficconverterBizJson = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xb4\x55\xdd\x6f\xe2\x46\x10\x7f\x86\xbf\x62\xe4\x87\xea\x4e\x0a\x36\x4e\xc9\xf5\x44\x75\x8a\xf8\x4a\x43\xcb\x97\x58\xa7\xc9\xa9\xea\xc3\x7a\x3d\xc6\x5b\xcc\xae\xbb\xbb\x0e\x71\x4f\xf7\xbf\x57\x5e\x1b\x42\xd4\x23\x41\xb4\x7d\x00\x21\x31\xf3\xfb\x9a\x9d\xdd\x2f\xcd\x86\xd3\x9f\xf4\x06\xbf\x4c\xc6\x24\x70\xba\xf0\xa5\xd9\x68\x38\xe3\xd9\xcd\xdc\xe9\xc2\x6f\xcd\x46\xa3\x61\xbf\x1a\xce\x50\x6e\x28\x17\xc0\x52\xa4\x02\xc2\x02\x7e\x92\x72\x95\x22\x10\x1a\x23\xf4\x95\xdc\x6a\x2e\x56\x5d\x30\x8a\xc6\x31\x67\x4c\x8a\x47\x54\x06\x95\x1b\xf2\xbf\x9c\x8b\x0a\x21\x31\x26\xeb\x7a\x9e\xa6\x31\x86\x75\x83\xcb\x52\x8e\xc2\x68\x77\x65\xd1\x5c\x26\x37\x2f\xfe\xf7\x22\x4e\x57\x42\x6a\xc3\xd9\xb5\xe6\x06\x3f\x7d\x13\xbf\x84\xff\xfd\xe2\x15\xad\x33\xa9\x8c\x14\x95\xd6\x7b\x0c\x4f\x96\xb9\xc5\xd0\x15\xb6\xd7\x2a\x53\x98\x49\x65\x3c\x9d\xc8\xed\x75\xae\xd2\x73\xc4\x48\x01\x8b\x84\xeb\x24\xa0\x62\x7d\x92\x8c\xed\x76\xeb\x66\x65\x87\xa1\x62\x6d\x55\xbc\xcd\x60\x12\x84\x79\x86\x8a\x82\xcd\x11\xd5\x49\x4c\xb2\xec\x38\x85\x21\x2c\x2c\x03\xc9\x59\xae\x38\x4c\x69\xba\xa5\x0a\x61\x42\x43\x7d\x12\x4f\x4a\x43\xed\x6a\xdb\xec\x0a\x34\xde\x75\x98\x52\xb6\x4e\xb9\x36\x67\x06\x4a\x32\xba\xb9\xa5\xb9\x86\x61\x7f\x72\x72\xa6\x3a\xa3\x9b\x84\xe6\xda\x95\x6a\xe5\xfd\x99\xa3\x2a\xbc\xc8\xe2\x7a\xe7\x89\xf8\x4c\x45\x84\x4f\xf0\xee\x91\x53\x20\x32\x4b\xa4\x7e\x7f\xb2\x96\xc2\xf6\xda\xe8\xb9\x88\x91\x19\x8c\x8e\x9e\xaf\xef\xe8\x26\xfb\x31\xf5\xdb\xe2\x13\x8a\xb7\xe7\x34\x22\xa3\xe0\xbc\xa1\xa0\x46\x53\xe1\x37\x6b\x0e\xe7\xbe\xb7\x9c\x7d\xfb\x52\xd8\x4f\x10\xa3\x92\x95\x70\x83\xbd\xe8\x91\x6b\xa9\xe0\xdd\x94\xf5\x62\xc4\xd3\xc3\x28\xd7\x9c\x56\xcd\xd5\x75\xc0\x0d\xea\x57\x86\xd2\xb4\x9f\xaf\x17\xcd\x86\xb3\x1c\x0d\xe6\xd3\xe9\x68\x36\xec\x05\xe3\xf9\x8c\xd4\x5a\xad\x54\x87\x60\xe9\xcd\x14\x70\x8b\x34\x2a\x37\xe2\xa1\xf5\x40\x48\x6b\xa1\xa4\x41\x66\xb8\x14\x30\xe5\xba\xbc\x72\x2a\x49\xce\x3d\x42\xc4\x23\x10\xd2\x40\xcc\x45\x64\x4f\xbc\x42\x26\x37\x1b\x14\x11\x46\xa0\x77\x78\x89\xc5\x83\x58\x2a\x78\x20\x04\x0e\x00\xa5\x80\x42\xe6\x0a\x4a\x07\x2e\xd4\xb8\xb5\xd3\x75\x78\x98\xf6\x96\x2a\xc1\xc5\x4a\x7b\x09\x55\x11\x96\x3f\xbd\x0a\x56\xb7\x9e\x5a\x4f\x5a\xb7\xb2\x3d\xaa\xb3\x1b\xc7\x51\x5b\x37\x8a\x6e\xb0\x35\xcf\xca\x6a\xfd\x2f\xdc\x0c\x52\xce\xd6\x3f\x53\xb6\xe6\x62\xf5\x3f\xd8\x8a\xad\x4c\x56\x92\xfc\x51\x91\xbc\x6d\x6d\x20\x85\x41\x61\x5a\x41\x91\x21\x08\xa9\x05\x8f\xe3\x33\x1d\x1a\x09\x99\xc2\x47\x14\x06\x6a\x54\xb0\xa8\x16\xb3\x74\xfc\x1f\xd9\x64\xb5\x64\x53\x64\xe8\x54\x67\xb5\xf4\xe8\x90\x41\x6f\xb6\x7b\x6d\x87\xf3\x69\x6f\xbc\x5f\x2d\xe7\xd8\x59\xaf\xb6\x70\xbc\xd8\x17\x7e\xff\xd1\xf5\xdb\x97\xae\x7f\xd5\x76\x2f\x3f\x3e\x57\x90\x71\x30\xda\xd7\xd4\x8a\x8f\x62\xd6\xab\x43\x3e\x93\x60\x34\xdd\x09\x1a\x2d\x97\xf3\xe5\x1e\xe2\x4e\xd0\x30\xc5\x2a\xb1\xf2\x91\x48\x0b\xd0\x8c\xbe\x88\xa7\xdc\x78\x50\x68\x72\x9b\x04\xa0\x52\xe5\xea\x77\xda\x4f\xef\xbb\x00\xb7\x41\xb0\xf0\x7c\xd7\x87\x4e\xbb\x03\x33\x69\xe0\x46\xe6\x22\x3a\x64\xff\x75\xb4\x24\xe3\xf9\x3e\x8f\xfe\xdd\x78\x32\x1c\xf6\x0e\x5c\xf8\x1d\x18\x22\x83\xcb\xb6\xff\x03\xf8\x1f\xba\x57\x1f\xe0\x2e\x18\x3c\x3b\x1e\xcc\xa7\x8b\xf1\x64\x74\xbc\xe7\xd2\xff\x47\xcf\xb0\xff\xb2\xda\x3f\xa8\x6e\x77\xdb\x57\x2f\xab\x9f\x15\xd6\xe5\x6e\x67\x67\xa0\xf9\xb5\xf9\x77\x00\x00\x00\xff\xff\xd2\x40\x38\x8c\x44\x09\x00\x00")

func testdataScanTrafficconverterBizJsonBytes() ([]byte, error) {
	return bindataRead(
		_testdataScanTrafficconverterBizJson,
		"testdata/scan-trafficconverter.biz.json",
	)
}

func testdataScanTrafficconverterBizJson() (*asset, error) {
	bytes, err := testdataScanTrafficconverterBizJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/scan-trafficconverter.biz.json", size: 2372, mode: os.FileMode(420), modTime: time.Unix(1516320506, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"testdata/scan-johnhackedsite.com.json": testdataScanJohnhackedsiteComJson,
	"testdata/scan-google.com.json": testdataScanGoogleComJson,
	"testdata/scan-trafficconverter.biz.json": testdataScanTrafficconverterBizJson,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}
var _bintree = &bintree{nil, map[string]*bintree{
	"testdata": &bintree{nil, map[string]*bintree{
		"scan-google.com.json": &bintree{testdataScanGoogleComJson, map[string]*bintree{}},
		"scan-johnhackedsite.com.json": &bintree{testdataScanJohnhackedsiteComJson, map[string]*bintree{}},
		"scan-trafficconverter.biz.json": &bintree{testdataScanTrafficconverterBizJson, map[string]*bintree{}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}

