package main

import (
	"fmt"
	"log"

	"github.com/miracl/amcl/gen"
)

const (
	tmplFileName   = "gen/ecdsa/ecdsa.go.tmpl"
	fileNameFormat = "ecdsa_%v_generated.go"
)

func main() {

	curves := []string{"BLS383", "BN254", "BN254CX", "ED25519", "GOLDILOCKS", "NIST256"}

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
