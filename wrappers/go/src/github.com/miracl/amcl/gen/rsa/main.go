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
