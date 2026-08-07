#!/bin/sh
set -eu
spec_path="${OPENAPI_SPEC:-../../../complicatedauth-openapi/openapi.yaml}"
go tool oapi-codegen -config oapi-codegen.yaml "$spec_path"
