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

type arg struct {
	Name, CType string
	Ref         bool
}

type funcCtx struct {
	// raw c declaration
	c string

	// Parsed definition
	CType string
	CName string
	Args  []arg
}

var (
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
	mPinPerCurveFuncs = []funcCtx{
		{c: "int MPIN_{{.curve}}_CLIENT_1(int h, int d, octet* ID, csprng* R, octet* x, int pin, octet* T, octet* S, octet* U, octet* UT, octet* TP)"},
		{c: "int MPIN_{{.curve}}_CLIENT_2(octet* x, octet* y, octet* V)"},
		{c: "int MPIN_{{.curve}}_CLIENT_KEY(int h, octet* g1, octet* g2, int pin, octet* r, octet* x, octet* p, octet* T, octet* K)"},
		{c: "int MPIN_{{.curve}}_CLIENT(int h, int d, octet* ID, csprng* R, octet* x, int pin, octet* T, octet* V, octet* U, octet* UT, octet* TP, octet* MESSAGE, int t, octet* y)"},
		{c: "int MPIN_{{.curve}}_EXTRACT_PIN(int h, octet* ID, int pin, octet* CS)"},
		{c: "int MPIN_{{.curve}}_GET_CLIENT_PERMIT(int h, int d, octet* S, octet* ID, octet* TP)"},
		{c: "int MPIN_{{.curve}}_GET_CLIENT_SECRET(octet* S, octet* ID, octet* CS)"},
		{c: "int MPIN_{{.curve}}_GET_DVS_KEYPAIR(csprng* R, octet* Z, octet* Pa)"},
		{c: "int MPIN_{{.curve}}_GET_G1_MULTIPLE(csprng* R, int t, octet* x, octet* G, octet* W)"},
		{c: "int MPIN_{{.curve}}_GET_SERVER_SECRET(octet* S, octet* SS)"},
		{c: "int MPIN_{{.curve}}_KANGAROO(octet* E, octet* F)"},
		{c: "int MPIN_{{.curve}}_PRECOMPUTE(octet* T, octet* ID, octet* CP, octet* g1, octet* g2)"},
		{c: "int MPIN_{{.curve}}_RANDOM_GENERATE(csprng* R, octet* S)"},
		{c: "int MPIN_{{.curve}}_RECOMBINE_G1(octet* Q1, octet* Q2, octet* Q)"},
		{c: "int MPIN_{{.curve}}_RECOMBINE_G2(octet* P1, octet* P2, octet* P)"},
		{c: "int MPIN_{{.curve}}_SERVER_2(int d, octet* HID, octet* HTID, octet* y, octet* SS, octet* U, octet* UT, octet* V, octet* E, octet* F, octet* Pa)"},
		{c: "int MPIN_{{.curve}}_SERVER_KEY(int h, octet* Z, octet* SS, octet* w, octet* p, octet* I, octet* U, octet* UT, octet* K)"},
		{c: "int MPIN_{{.curve}}_SERVER(int h, int d, octet* HID, octet* HTID, octet* y, octet* SS, octet* U, octet* UT, octet* V, octet* E, octet* F, octet* ID, octet* MESSAGE, int t, octet* Pa)"},
		{c: "void MPIN_{{.curve}}_SERVER_1(int h, int d, octet* ID, octet* HID, octet* HTID)"},
	}

	rsaKeySizes   = []string{"2048", "3072", "4096"}
	rsaPerKeyFunc = []funcCtx{
		{c: "void RSA_{{.keySize}}_DECRYPT(rsa_private_key_{{.keySize}}* priv, octet* G, octet* F)"},
		{c: "void RSA_{{.keySize}}_ENCRYPT(rsa_public_key_{{.keySize}}* pub, octet* F, octet* G)"},
		{c: "void RSA_{{.keySize}}_KEY_PAIR(csprng* rng, sign32 e, rsa_private_key_{{.keySize}}* priv, rsa_public_key_{{.keySize}}* pub, octet* p, octet* q)"},
		{c: "void RSA_{{.keySize}}_PRIVATE_KEY_KILL(rsa_private_key_{{.keySize}}* PRIV)"},
	}

	funcSets = map[string]func() map[string][]funcCtx{
		"mpin": func() map[string][]funcCtx {
			return genMPinFuncs(mPinPerCurveFuncs, mPinCurves)
		},
		"rand": func() map[string][]funcCtx {
			return map[string][]funcCtx{
				"": {funcCtx{c: "void CREATE_CSPRNG(csprng* R, octet* S)"}},
			}
		},
		"rsa": func() map[string][]funcCtx {
			fileFuncMap := genRSAFuncs(rsaPerKeyFunc, rsaKeySizes)

			fileFuncMap[""] = []funcCtx{
				{c: "int PKCS15(int h, octet* m, octet* w)"},
				{c: "int OAEP_ENCODE(int h, octet* m, csprng* rng, octet* p, octet* f)"},
				{c: "int OAEP_DECODE(int h, octet* p, octet* f)"},
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

	// Get the selected set of function
	getFuncs, ok := funcSets[fSetName]
	if !ok {
		log.Fatal("invalid function set", fSetName)
	}
	funcs := getFuncs()

	i := 0
	files := make([]gen.File, len(funcs))
	for suffix, funcs := range funcs {

		// parse the c definition and add it to the context
		for i, funcDef := range funcs {
			funcs[i].CType, funcs[i].CName, funcs[i].Args = parseCFuncDef(funcDef.c)
		}

		fileName := fmt.Sprintf("%v_%v_wrappers_generated.go", fSetName, suffix)
		if suffix == "" {
			fileName = fmt.Sprintf("%v_wrappers_generated.go", fSetName)
		}

		files[i] = gen.File{
			Path:     fileName,
			TmplPath: tmplFile,
			Ctx: struct {
				Funcs  []funcCtx
				Suffix string
			}{
				Funcs:  funcs,
				Suffix: suffix,
			},
		}
		i++
	}

	if err := gen.GenerateFiles(files...); err != nil {
		log.Fatal(err)
	}
}

func genMPinFuncs(funcs []funcCtx, curves []string) map[string][]funcCtx {
	rFuncs := map[string][]funcCtx{}

	for _, c := range curves {
		rList := make([]funcCtx, len(funcs))
		for i, w := range funcs {
			tmpl := template.Must(template.New("func").Parse(w.c))

			var buff bytes.Buffer
			if err := tmpl.Execute(&buff, map[string]string{"curve": c}); err != nil {
				panic(err)
			}

			rList[i] = funcCtx{c: buff.String()}
		}
		rFuncs[c] = rList
	}

	return rFuncs
}

func genRSAFuncs(funcs []funcCtx, sizes []string) map[string][]funcCtx {
	rFuncs := map[string][]funcCtx{}

	for _, s := range sizes {
		rList := make([]funcCtx, len(funcs))
		for i, f := range funcs {
			tmpl := template.Must(template.New("func").Parse(f.c))

			var buff bytes.Buffer
			if err := tmpl.Execute(&buff, map[string]string{"keySize": s}); err != nil {
				panic(err)
			}

			rList[i] = funcCtx{c: buff.String()}
		}
		rFuncs[s] = rList
	}

	return rFuncs
}

func parseCFuncDef(def string) (cType, name string, args []arg) {
	match := cDefRe.FindStringSubmatch(def)

	for i, group := range cDefRe.SubexpNames() {
		switch group {
		case "type":
			cType = match[i]
		case "name":
			name = match[i]
		case "args":
			args = parseCArgs(match[i])
		}
	}

	return cType, name, args
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
