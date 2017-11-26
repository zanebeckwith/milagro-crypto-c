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
