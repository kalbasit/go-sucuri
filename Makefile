.PHONY: go-bindata assets

assets: testdata/asset.go

go-bindata:
	@which go-bindata &> /dev/null || go get -u github.com/jteeuwen/go-bindata/go-bindata

testdata/asset.go: go-bindata $(filter-out $(wildcard testdata/*.go), $(wildcard testdata/*))
	@go-bindata -o testdata/asset.go -pkg testdata $(filter-out $(wildcard testdata/*.go), $(wildcard testdata/*))
