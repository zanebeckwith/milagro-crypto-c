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

package main

import (
	"fmt"
	"log"

	"github.com/miracl/amcl/gen"
)

const (
	tmplFileName   = "gen/rsa/rsa.go.tmpl"
	fileNameFormat = "rsa_%v_generated.go"
)

func main() {

	sizes := []string{"2048", "3072", "4096"}

	files := []gen.File{}
	for _, size := range sizes {
		files = append(files, gen.File{
			Path:     fmt.Sprintf(fileNameFormat, size),
			TmplPath: tmplFileName,
			Ctx:      map[string]string{"keySize": size},
		})
	}

	if err := gen.GenerateFiles(files...); err != nil {
		log.Fatal(err)
	}
}
