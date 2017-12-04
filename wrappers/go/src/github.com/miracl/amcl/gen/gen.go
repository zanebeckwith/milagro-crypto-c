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

package gen

import (
	"bytes"
	"io/ioutil"
	"os"
	"text/template"
)

type File struct {
	Path     string
	TmplPath string
	Ctx      interface{}
}

// GenerateFiles generates files given template
func GenerateFiles(files ...File) (err error) {

	tmplCache := templates{}

	for _, f := range files {

		tmpl, err := tmplCache.get(f.TmplPath)
		if err != nil {
			return err
		}

		var fileBody bytes.Buffer
		if err := tmpl.Execute(&fileBody, f.Ctx); err != nil {
			return err
		}

		if err := ioutil.WriteFile(f.Path, fileBody.Bytes(), 0664); err != nil {
			return err
		}

	}

	return nil
}

type templates map[string]*template.Template

func (t *templates) get(path string) (*template.Template, error) {

	// Check the cache
	tmpl, ok := (*t)[path]
	if ok {
		return tmpl, nil
	}

	// Create and cache the template
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	tmplBody, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	cfgTmpl, err := template.New("main").Parse(string(tmplBody))
	if err != nil {
		return nil, err
	}

	(*t)[path] = cfgTmpl
	return cfgTmpl, nil
}
