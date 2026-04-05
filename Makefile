BINARY_NAME=mtproxy_stats
VERSION=1.0.2
DATE=$(shell date -u +'%Y-%m-%d %I:%M:%S%p %Z')

build:
	GOARCH=amd64 GOOS=linux go build -o ${BINARY_NAME} -ldflags "-X 'main.version=${VERSION}' -X 'main.date=${DATE}'" ./mtproxy_stats.go
	GOARCH=amd64 GOOS=windows go build -o ${BINARY_NAME}.exe -ldflags "-X 'main.version=${VERSION}' -X 'main.date=${DATE}'" ./mtproxy_stats.go

run:
	./${BINARY_NAME}

build_and_run: build run

clean:
	# go clean
	rm ${BINARY_NAME}
	rm ${BINARY_NAME}.exe