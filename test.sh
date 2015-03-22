#/bin/bash
docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp authproxy sh -c "go test"
