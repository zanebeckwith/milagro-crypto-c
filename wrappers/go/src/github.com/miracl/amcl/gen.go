// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package amcl

//go:generate go run gen/wrappers/main.go ecdsa ecdsa_wrappers.go.tmpl
//go:generate go run gen/wrappers/main.go mpin mpin_wrappers.go.tmpl
//go:generate go run gen/wrappers/main.go mpin_kangaroo mpin_wrappers.go.tmpl
//go:generate go run gen/wrappers/main.go pbc pbc_wrappers.go.tmpl
//go:generate go run gen/wrappers/main.go rand rand_wrappers.go.tmpl
//go:generate go run gen/wrappers/main.go rsa rsa_wrappers.go.tmpl
//go:generate gofmt -s -w .
