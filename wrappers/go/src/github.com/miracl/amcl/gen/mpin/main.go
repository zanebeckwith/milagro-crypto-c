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
	"os"

	"github.com/miracl/amcl/gen"
)

const fileNameFormat = "mpin_%v_generated.go"

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("expects one argument - path to template file, got %v", len(os.Args)-1)
	}
	tmplFileName := os.Args[1]

	curves := []string{"BLS383", "BN254", "BN254CX"}

	files := []gen.File{}
	for _, curve := range curves {
		files = append(files, gen.File{
			Path:     fmt.Sprintf(fileNameFormat, curve),
			TmplPath: tmplFileName,
			Ctx:      map[string]string{"curve": curve},
		})
	}

	if err := gen.GenerateFiles(files...); err != nil {
		log.Fatal(err)
	}
}