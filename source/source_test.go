package source

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func good() Repository {
	return Repository{Kind: "GitHub", CloneURL: "https://GitHub.com/acme/api.git", Branch: "release/1.2",
		Commit: strings.Repeat("AB", 20), Capabilities: []string{"sast.code@1", "secrets.code@1", "sast.code@1"}, Credential: "scm"}
}

func TestValidateNormalizes(t *testing.T) {
	r := good()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if r.Kind != KindGitHub || r.CloneURL != "https://github.com/acme/api.git" || r.Commit != strings.Repeat("ab", 20) ||
		r.Depth != 1 || len(r.Capabilities) != 2 || r.Host() != "github.com" {
		t.Fatalf("%+v", r)
	}
	r = good()
	r.Commit = strings.Repeat("a", 64)
	r.Depth = MaxDepth
	r.Credential = ""
	r.CloneURL = "https://git.corp.example:8443/group/sub/repo"
	if err := r.Validate(); err != nil {
		t.Fatalf("SHA-256 commit, history depth, port, nested group: %v", err)
	}
}

func TestValidateRefuses(t *testing.T) {
	cases := map[string]func(*Repository){
		"unknown kind":       func(r *Repository) { r.Kind = "svn" },
		"http":               func(r *Repository) { r.CloneURL = "http://github.com/acme/api" },
		"ssh":                func(r *Repository) { r.CloneURL = "ssh://git@github.com/acme/api" },
		"scp form":           func(r *Repository) { r.CloneURL = "git@github.com:acme/api.git" },
		"file":               func(r *Repository) { r.CloneURL = "file:///etc/passwd" },
		"ext transport":      func(r *Repository) { r.CloneURL = "ext::sh -c touch% /tmp/x" },
		"userinfo":           func(r *Repository) { r.CloneURL = "https://x-access-token:ghs_abc@github.com/acme/api" },
		"query":              func(r *Repository) { r.CloneURL = "https://github.com/acme/api?x=1" },
		"fragment":           func(r *Repository) { r.CloneURL = "https://github.com/acme/api#x" },
		"ip host":            func(r *Repository) { r.CloneURL = "https://169.254.169.254/latest/meta" },
		"ipv6 host":          func(r *Repository) { r.CloneURL = "https://[::1]/acme/api" },
		"single label host":  func(r *Repository) { r.CloneURL = "https://localhost/acme/api" },
		"no repo path":       func(r *Repository) { r.CloneURL = "https://github.com/acme" },
		"dot dot":            func(r *Repository) { r.CloneURL = "https://github.com/acme/../admin" },
		"option segment":     func(r *Repository) { r.CloneURL = "https://github.com/acme/--upload-pack=x" },
		"hidden segment":     func(r *Repository) { r.CloneURL = "https://github.com/acme/.git" },
		"escaped path":       func(r *Repository) { r.CloneURL = "https://github.com/acme/a%2Fb" },
		"space":              func(r *Repository) { r.CloneURL = "https://github.com/acme/a b" },
		"bad port":           func(r *Repository) { r.CloneURL = "https://github.com:0443/acme/api" },
		"branch option":      func(r *Repository) { r.Branch = "--orphan" },
		"branch dotdot":      func(r *Repository) { r.Branch = "a..b" },
		"branch reflog":      func(r *Repository) { r.Branch = "main@{1}" },
		"branch lock":        func(r *Repository) { r.Branch = "main.lock" },
		"branch space":       func(r *Repository) { r.Branch = "a b" },
		"branch empty":       func(r *Repository) { r.Branch = "" },
		"short commit":       func(r *Repository) { r.Commit = "abcdef1" },
		"commit not hex":     func(r *Repository) { r.Commit = strings.Repeat("g", 40) },
		"depth negative":     func(r *Repository) { r.Depth = -1 },
		"depth too deep":     func(r *Repository) { r.Depth = MaxDepth + 1 },
		"credential value":   func(r *Repository) { r.Credential = "ghs_0123456789ABCDEF" },
		"no capability":      func(r *Repository) { r.Capabilities = nil },
		"unknown capability": func(r *Repository) { r.Capabilities = []string{"sast.code@9"} },
		"network capability": func(r *Repository) { r.Capabilities = []string{"discover.hosts@1"} },
		"too many capability": func(r *Repository) {
			r.Capabilities = nil
			for i := range 17 {
				r.Capabilities = append(r.Capabilities, "sast.code@"+strings.Repeat("1", i+1))
			}
		},
	}
	for name, mut := range cases {
		r := good()
		mut(&r)
		err := r.Validate()
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if strings.Contains(err.Error(), "ghs_abc") {
			t.Errorf("%s: the error echoes a credential: %v", name, err)
		}
	}
}

func TestJSONShape(t *testing.T) {
	r := good()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"kind":"github","clone_url":"https://github.com/acme/api.git","branch":"release/1.2","commit":"` +
		strings.Repeat("ab", 20) + `","depth":1,"credential":"scm","capabilities":["sast.code@1","secrets.code@1"]}`
	if string(b) != want {
		t.Fatalf("\n got %s\nwant %s", b, want)
	}
}

// Whatever Validate accepts is an https URL with a DNS host and no user
// information, a ref-safe branch and a full commit id.
func FuzzValidate(f *testing.F) {
	f.Add("https://github.com/acme/api.git", "main", strings.Repeat("ab", 20))
	f.Add("https://u:p@1.2.3.4/a/b", "--x", "abc")
	f.Add("https://git.example.com:8443/g/s/r", "release/1.0", strings.Repeat("c", 64))
	f.Fuzz(func(t *testing.T, u, branch, commit string) {
		r := Repository{Kind: KindGit, CloneURL: u, Branch: branch, Commit: commit, Capabilities: []string{"sast.code@1"}}
		if r.Validate() != nil {
			return
		}
		if !strings.HasPrefix(r.CloneURL, "https://") || strings.Contains(r.CloneURL, "@") || strings.ContainsAny(r.CloneURL, "?# \\") {
			t.Fatalf("accepted URL %q", r.CloneURL)
		}
		if strings.HasPrefix(r.Branch, "-") || strings.Contains(r.Branch, "..") || !commitRe.MatchString(r.Commit) {
			t.Fatalf("accepted %q %q", r.Branch, r.Commit)
		}
	})
}
