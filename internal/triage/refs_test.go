package triage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadCountsReferences(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"src/Foo.php":            "<?php class Foo {}",
		"src/Bar.php":            "<?php new Foo(); // Foo",
		"src/Baz.php":            "<?php new FooBar();", // not a whole word
		"tests/FooTest.php":      "Foo",                 // tests are not references
		"templates/x.html.twig":  "x",
		"src/UsesTemplate.php":   "render('templates/x.html.twig')",
		"config/services.yaml":   "Foo: ~",
		"bin/blob":               "Foo\x00\x00",
		"src/Foo.php.orig":       "",
		"src/New.php.notonddisk": "",
	}
	var tree []string
	for p, c := range files {
		assert.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755))
		assert.NoError(t, os.WriteFile(filepath.Join(root, p), []byte(c), 0o644))
		tree = append(tree, p)
	}
	refs, content, _ := Load(root, []string{"src/Foo.php", "templates/x.html.twig", "src/Missing.php"}, tree, []string{"tests/**"})
	assert.Equal(t, map[string]int{"src/Foo.php": 2, "templates/x.html.twig": 1}, refs) // Bar.php, services.yaml; UsesTemplate.php
	assert.Contains(t, content["src/Foo.php"], "class Foo")
}
