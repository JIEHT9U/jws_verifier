lint:
	@gofmt -w  -s .
	@goimports -e  -local github.com/jieht9u/google-auth-id-token-verifier -w .
	@golint .

test:
	@go test -v .