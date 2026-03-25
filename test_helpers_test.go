package tripwire

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func loadFixture[T any](t *testing.T, relativePath string) T {
	t.Helper()
	root := "."
	path := filepath.Join(root, "spec", "fixtures", filepath.FromSlash(relativePath))
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", relativePath, err)
	}
	var value T
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatalf("decode fixture %s: %v", relativePath, err)
	}
	return value
}
