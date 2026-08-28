package stogas

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestEveryFuzzTargetHasScheduledCampaign(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join("..", ".."))
	workflow, err := os.ReadFile(filepath.Join(repositoryRoot, ".github", "workflows", "fuzz.yml"))
	if err != nil {
		t.Fatalf("read scheduled fuzz workflow: %v", err)
	}
	workflowText := string(workflow)
	if !strings.Contains(workflowText, "path: ~/.cache/go-build/fuzz") ||
		!strings.Contains(workflowText, "github.run_id") ||
		!strings.Contains(workflowText, "working-directory: ${{ matrix.module }}") ||
		!strings.Contains(workflowText, "go-version-file: ${{ matrix.module }}/go.mod") ||
		!strings.Contains(workflowText, "path: ${{ matrix.module }}/**/testdata/fuzz/${{ matrix.target }}") {
		t.Error("scheduled fuzzing must restore and advance each generated corpus")
	}

	declaration := regexp.MustCompile(`(?m)^func (Fuzz[A-Za-z0-9_]+)\s*\(`)
	type fuzzTarget struct {
		module      string
		name        string
		packageName string
	}
	var targets []fuzzTarget
	targetNames := make(map[string]string)
	for _, module := range []string{"core", "transports"} {
		moduleRoot := filepath.Join(repositoryRoot, module)
		err = filepath.WalkDir(moduleRoot, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				if entry.Name() == "vendor" || strings.HasPrefix(entry.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			source, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			packagePath, relativeErr := filepath.Rel(moduleRoot, filepath.Dir(path))
			if relativeErr != nil {
				return relativeErr
			}
			packageName := "."
			if packagePath != "." {
				packageName = "./" + filepath.ToSlash(packagePath)
			}
			for _, match := range declaration.FindAllSubmatch(source, -1) {
				name := string(match[1])
				location := module + "/" + filepath.ToSlash(packagePath)
				if previous, exists := targetNames[name]; exists {
					t.Errorf("fuzz target name %s is duplicated in %s and %s", name, previous, location)
					continue
				}
				targetNames[name] = location
				targets = append(targets, fuzzTarget{module: module, name: name, packageName: packageName})
			}
			return nil
		})
		if err != nil {
			t.Fatalf("inventory %s fuzz targets: %v", module, err)
		}
	}
	if len(targets) == 0 {
		t.Fatal("gateway has no fuzz targets")
	}

	sort.Slice(targets, func(i, j int) bool {
		if targets[i].module != targets[j].module {
			return targets[i].module < targets[j].module
		}
		if targets[i].packageName != targets[j].packageName {
			return targets[i].packageName < targets[j].packageName
		}
		return targets[i].name < targets[j].name
	})
	for _, target := range targets {
		entry := regexp.MustCompile(
			`(?m)- module:\s*` + regexp.QuoteMeta(target.module) +
				`\s*\n\s*package:\s*` + regexp.QuoteMeta(target.packageName) +
				`\s*\n\s*target:\s*` + regexp.QuoteMeta(target.name) + `\s*$`,
		)
		if !entry.MatchString(workflowText) {
			t.Errorf(
				"fuzz target %s in %s/%s is absent from .github/workflows/fuzz.yml",
				target.name,
				target.module,
				target.packageName,
			)
		}
	}
}
