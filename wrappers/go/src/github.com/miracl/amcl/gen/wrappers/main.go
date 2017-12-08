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
	"regexp"
	"strings"
	"text/template"

	"github.com/miracl/amcl/gen"
)

var (
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

	wrapFilePath      = "wrappers_generated.c"
	wrapFileTmplPath  = "gen/wrappers/wrappers.c.tmpl"
	wrapHFilePath     = "wrappers_generated.h"
	wrapHFileTmplPath = "gen/wrappers/wrappers.h.tmpl"
)

func main() {
	var (
		cWrapFuncs = []string{
			"int PKCS15(int h, octet* m, octet* w)",
			"int OAEP_ENCODE(int h, octet* m, csprng* rng, octet* p, octet* f)",
			"int OAEP_DECODE(int h, octet* p, octet* f)",
			"void CREATE_CSPRNG(csprng* R, octet* S)",
		}

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
			"int MPIN_{{.curve}}_GET_G1_MULTIPLE(csprng* R, int type, octet* x, octet* G, octet* W)",
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

		rsaKeySizes   = []int{2048, 3072, 4096}
		rsaPerKeyFunc = []string{
			"void RSA_{{.keySize}}_DECRYPT(rsa_private_key_{{.keySize}}* priv, octet* G, octet* F)",
			"void RSA_{{.keySize}}_ENCRYPT(rsa_public_key_{{.keySize}}* pub, octet* F, octet* G)",
			"void RSA_{{.keySize}}_KEY_PAIR(csprng* rng, sign32 e, rsa_private_key_{{.keySize}}* priv, rsa_public_key_{{.keySize}}* pub, octet* p, octet* q)",
			"void RSA_{{.keySize}}_PRIVATE_KEY_KILL(rsa_private_key_{{.keySize}}* PRIV)",
		}
	)

	cWrapFuncs = appendSlices(
		cWrapFuncs,
		genRSAFuncs(rsaPerKeyFunc, rsaKeySizes),
		genMPinFuncs(mPinPerCurveFuncs, mPinCurves),
	)

	cWraps := genCWrapFuncs(cWrapFuncs)
	err := gen.GenerateFiles(
		cWraps...,
	)
	if err != nil {
		log.Fatal(err)
	}
}

func genMPinFuncs(funcs, curves []string) []string {
	rFuncs := make([]string, len(funcs)*len(curves))
	for i, f := range funcs {
		tmpl := template.Must(template.New("func").Parse(f))

		for j, c := range curves {
			var buff bytes.Buffer
			if err := tmpl.Execute(&buff, map[string]string{"curve": c}); err != nil {
				panic(err)
			}
			rFuncs[i*len(curves)+j] = buff.String()
		}
	}

	return rFuncs
}

func genRSAFuncs(funcs []string, sizes []int) []string {
	rFuncs := make([]string, len(funcs)*len(sizes))
	for i, f := range funcs {
		tmpl := template.Must(template.New("func").Parse(f))

		for j, s := range sizes {
			var buff bytes.Buffer
			if err := tmpl.Execute(&buff, map[string]int{"keySize": s}); err != nil {
				panic(err)
			}
			rFuncs[i*len(sizes)+j] = buff.String()
		}
	}

	return rFuncs
}

type cWrap struct {
	cFuncDef
	WArgs []arg
}

func genCWrapFuncs(funcs []string) []gen.File {
	cWraps := make([]cWrap, len(funcs))
	for fi, funcDef := range funcs {
		cf := parseCFuncDef(funcDef)

		wArgs := make([]arg, len(cf.Args))
		for ai, a := range cf.Args {
			wArgs[ai] = arg{
				Name:  a.Name,
				CType: a.CType,
			}

			if a.CType == "octet*" {
				wArgs[ai].CType = strings.TrimRight(a.CType, "*")
			}
		}

		cWraps[fi] = cWrap{
			cFuncDef: *cf,
			WArgs:    wArgs,
		}

	}

	return []gen.File{
		gen.File{
			Path:     wrapFilePath,
			TmplPath: wrapFileTmplPath,
			Ctx:      cWraps,
		},
		gen.File{
			Path:     wrapHFilePath,
			TmplPath: wrapHFileTmplPath,
			Ctx:      cWraps,
		},
	}

}

type cFuncDef struct {
	Name  string
	CType string
	Args  []arg
}

type arg struct {
	Name, CType string
	Pointer     bool
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
			Name:    n,
			CType:   t,
			Pointer: strings.HasSuffix(t, "*"),
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
