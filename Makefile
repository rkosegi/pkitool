# Copyright 2024 Richard Kosegi
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.PHONY: test clean build build-all

.DEFAULT_GOAL := build

clean:
	rm -fr dist *.key *.pem

lint:
	pre-commit run --all-files

test:
	go test -v ./...

build:
	goreleaser build --snapshot --clean --single-target

build-all:
	goreleaser build --snapshot --clean

update-go-deps:
	@for m in $$(go list -mod=readonly -m -f '{{ if and (not .Indirect) (not .Main)}}{{.Path}}{{end}}' all); do \
		go get $$m; \
	done
	@go mod tidy
