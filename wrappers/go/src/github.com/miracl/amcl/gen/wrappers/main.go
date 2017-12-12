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
	"bytes"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"text/template"

	"github.com/miracl/amcl/gen"
)

var (
	// constants related to file generation
	wrapFilePath      = "wrappers_generated.c"
	wrapFileTmplPath  = "wrappers.c.tmpl"
	wrapHFilePath     = "wrappers_generated.h"
	wrapHFileTmplPath = "wrappers.h.tmpl"

	// constants related to C function parsing
	cDefRe       = regexp.MustCompile(`^(?P<type>\S+) (?P<name>[^\(]+) ?\((?P<args>([^,],?)+)\)$`)
	cArgReCTypes = []string{
		`csprng\*`,
		`int`,
		`octet\*`,
		`rsa_private_key_2048\*`,
		`rsa_public_key_2048\*`,
		`rsa_private_key_3072\*`,
		`rsa_public_key_3072\*`,
		`rsa_private_key_4096\*`,
		`rsa_public_key_4096\*`,
		`sign32`,
	}
	cArgRe = regexp.MustCompile(
		fmt.Sprintf(
			`(?P<type>%v) (?P<name>[\d\w]+),?`,
			strings.Join(cArgReCTypes, "|"),
		),
	)

	// AMCL Functions

	mPinCurves        = []string{"BLS383", "BN254", "BN254CX"}
	mPinPerCurveFuncs = []string{
		"int MPIN_{{.curve}}_CLIENT_1(int h, int d, octet* ID, csprng* R, octet* x, int pin, octet* T, octet* S, octet* U, octet* UT, octet* TP)",
		"int MPIN_{{.curve}}_CLIENT_2(octet* x, octet* y, octet* V)",
		"int MPIN_{{.curve}}_CLIENT_KEY(int h, octet* g1, octet* g2, int pin, octet* r, octet* x, octet* p, octet* T, octet* K)",
		"int MPIN_{{.curve}}_CLIENT(int h, int d, octet* ID, csprng* R, octet* x, int pin, octet* T, octet* V, octet* U, octet* UT, octet* TP, octet* MESSAGE, int t, octet* y)",
		"int MPIN_{{.curve}}_EXTRACT_PIN(int h, octet* ID, int pin, octet* CS)",
		"int MPIN_{{.curve}}_GET_CLIENT_PERMIT(int h, int d, octet* S, octet* ID, octet* TP)",
		"int MPIN_{{.curve}}_GET_CLIENT_SECRET(octet* S, octet* ID, octet* CS)",
		"int MPIN_{{.curve}}_GET_DVS_KEYPAIR(csprng* R, octet* Z, octet* Pa)",
		"int MPIN_{{.curve}}_GET_G1_MULTIPLE(csprng* R, int t, octet* x, octet* G, octet* W)",
		"int MPIN_{{.curve}}_GET_SERVER_SECRET(octet* S, octet* SS)",
		"int MPIN_{{.curve}}_KANGAROO(octet* E, octet* F)",
		"int MPIN_{{.curve}}_PRECOMPUTE(octet* T, octet* ID, octet* CP, octet* g1, octet* g2)",
		"int MPIN_{{.curve}}_RANDOM_GENERATE(csprng* R, octet* S)",
		"int MPIN_{{.curve}}_RECOMBINE_G1(octet* Q1, octet* Q2, octet* Q)",
		"int MPIN_{{.curve}}_RECOMBINE_G2(octet* P1, octet* P2, octet* P)",
		"int MPIN_{{.curve}}_SERVER_2(int d, octet* HID, octet* HTID, octet* y, octet* SS, octet* U, octet* UT, octet* V, octet* E, octet* F, octet* Pa)",
		"int MPIN_{{.curve}}_SERVER_KEY(int h, octet* Z, octet* SS, octet* w, octet* p, octet* I, octet* U, octet* UT, octet* K)",
		"int MPIN_{{.curve}}_SERVER(int h, int d, octet* HID, octet* HTID, octet* y, octet* SS, octet* U, octet* UT, octet* V, octet* E, octet* F, octet* ID, octet* MESSAGE, int t, octet* Pa)",
		"void MPIN_{{.curve}}_SERVER_1(int h, int d, octet* ID, octet* HID, octet* HTID)",
	}

	rsaKeySizes   = []string{"2048", "3072", "4096"}
	rsaPerKeyFunc = []string{
		"void RSA_{{.keySize}}_DECRYPT(rsa_private_key_{{.keySize}}* priv, octet* G, octet* F)",
		"void RSA_{{.keySize}}_ENCRYPT(rsa_public_key_{{.keySize}}* pub, octet* F, octet* G)",
		"void RSA_{{.keySize}}_KEY_PAIR(csprng* rng, sign32 e, rsa_private_key_{{.keySize}}* priv, rsa_public_key_{{.keySize}}* pub, octet* p, octet* q)",
		"void RSA_{{.keySize}}_PRIVATE_KEY_KILL(rsa_private_key_{{.keySize}}* PRIV)",
	}

	funcSets = map[string]func() map[string][]string{
		"mpin": func() map[string][]string {
			return genMPinFuncs(mPinPerCurveFuncs, mPinCurves)
		},
		"rand": func() map[string][]string {
			return map[string][]string{
				"": {"void CREATE_CSPRNG(csprng* R, octet* S)"},
			}
		},
		"rsa": func() map[string][]string {
			fileFuncMap := genRSAFuncs(rsaPerKeyFunc, rsaKeySizes)

			fileFuncMap[""] = []string{
				"int PKCS15(int h, octet* m, octet* w)",
				"int OAEP_ENCODE(int h, octet* m, csprng* rng, octet* p, octet* f)",
				"int OAEP_DECODE(int h, octet* p, octet* f)",
			}

			return fileFuncMap
		},
	}
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("unexpected number of arguments (function set, template file path); expects 2; received", len(os.Args)-1)
	}
	fSetName, tmplFile := os.Args[1], os.Args[2]

	// TODO: Delete me
	if fSetName == "c" {
		funcs := []string{}
		for _, set := range funcSets {
			for _, fs := range set() {
				funcs = append(funcs, fs...)
			}
		}

		cWraps, _ := genCWrapFuncs(funcs)
		if err := gen.GenerateFiles(cWraps...); err != nil {
			log.Fatal(err)
		}
		return
	}

	funcsGetter, ok := funcSets[fSetName]
	if !ok {
		log.Fatal("invalid function set", fSetName)
	}

	funcs := funcsGetter()
	i := 0
	files := make([]gen.File, len(funcs))
	for suffix, funcs := range funcs {
		fileName := fmt.Sprintf("%v_%v_wrappers_generated.go", fSetName, suffix)
		if suffix == "" {
			fileName = fmt.Sprintf("%v_wrappers_generated.go", fSetName)
		}

		_, cFuncDefs := genCWrapFuncs(funcs)
		files[i] = gen.File{
			Path:     fileName,
			TmplPath: tmplFile,
			Ctx: struct {
				Funcs  []cWrap
				Suffix string
			}{
				Funcs:  cFuncDefs,
				Suffix: suffix,
			},
		}
		i++
	}

	if err := gen.GenerateFiles(files...); err != nil {
		log.Fatal(err)
	}
}

func genMPinFuncs(funcs, curves []string) map[string][]string {
	rFuncs := map[string][]string{}

	for _, c := range curves {
		rList := make([]string, len(funcs))
		for i, f := range funcs {
			tmpl := template.Must(template.New("func").Parse(f))

			var buff bytes.Buffer
			if err := tmpl.Execute(&buff, map[string]string{"curve": c}); err != nil {
				panic(err)
			}

			rList[i] = buff.String()
		}
		rFuncs[c] = rList
	}

	return rFuncs
}

func genRSAFuncs(funcs []string, sizes []string) map[string][]string {
	rFuncs := map[string][]string{}

	for _, s := range sizes {
		rList := make([]string, len(funcs))
		for i, f := range funcs {
			tmpl := template.Must(template.New("func").Parse(f))

			var buff bytes.Buffer
			if err := tmpl.Execute(&buff, map[string]string{"keySize": s}); err != nil {
				panic(err)
			}

			rList[i] = buff.String()
		}
		rFuncs[s] = rList
	}

	return rFuncs
}

type cWrap struct {
	cFuncDef
	WArgs  []arg
	GoArgs []arg
}

func genCWrapFuncs(funcs []string) ([]gen.File, []cWrap) {
	cWraps := make([]cWrap, len(funcs))
	for fi, funcDef := range funcs {
		cf := parseCFuncDef(funcDef)

		wArgs := make([]arg, len(cf.Args))
		for ai, a := range cf.Args {
			wArgs[ai] = arg{
				Name:  a.Name,
				CType: a.CType,
			}
		}

		cWraps[fi] = cWrap{
			cFuncDef: *cf,
			WArgs:    wArgs,
		}

	}

	return []gen.File{
		{
			Path:     wrapFilePath,
			TmplPath: wrapFileTmplPath,
			Ctx:      cWraps,
		},
		{
			Path:     wrapHFilePath,
			TmplPath: wrapHFileTmplPath,
			Ctx:      cWraps,
		},
	}, cWraps
}

type cFuncDef struct {
	Name  string
	CType string
	Args  []arg
}

type arg struct {
	Name, CType string
	Ref         bool
}

func parseCFuncDef(def string) *cFuncDef {
	match := cDefRe.FindStringSubmatch(def)

	f := &cFuncDef{}
	for i, name := range cDefRe.SubexpNames() {
		switch name {
		case "type":
			f.CType = match[i]
		case "name":
			f.Name = match[i]
		case "args":
			f.Args = parseCArgs(match[i])
		}
	}

	return f
}

func parseCArgs(str string) []arg {
	matches := cArgRe.FindAllStringSubmatch(str, -1)
	args := make([]arg, len(matches))
	for i, match := range matches {
		n, t := parseCArgsGroups(match)
		args[i] = arg{
			Name:  n,
			CType: strings.TrimRight(t, "*"),
			Ref:   strings.HasSuffix(t, "*"),
		}
	}
	return args
}

func parseCArgsGroups(match []string) (name, ctype string) {
	for i, groupName := range cArgRe.SubexpNames() {
		switch groupName {
		case "type":
			ctype = match[i]
		case "name":
			name = match[i]
		}
	}
	return name, ctype
}

func appendSlices(slices ...[]string) []string {
	var totalLen int
	for _, s := range slices {
		totalLen += len(s)
	}

	tmp := make([]string, totalLen)
	var i int
	for _, s := range slices {
		i += copy(tmp[i:], s)
	}

	return tmp
}