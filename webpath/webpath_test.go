package webpath

import (
	"strings"
	"testing"
)

func TestCleanPath(t *testing.T) {
	ok := map[string]string{
		"":              "/",
		"/":             "/",
		"/a/b/":         "/a/b/",
		"/x/../admin":   "/admin",
		"/%61dmin":      "/admin",
		"//admin":       "/admin",
		"/a\\..\\admin": "/admin",
		"/admin;x":      "/admin;x",
		"/a/./b":        "/a/b",
	}
	for in, want := range ok {
		got, err := CleanPath(in)
		if err != nil || got != want {
			t.Errorf("CleanPath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"/a%2fb", "/a%5Cb", "/a%00", "/a%zz", "/a\x01", "/..;/admin", "/a/.;x/b", "/%0d%0a"} {
		if got, err := CleanPath(in); err == nil {
			t.Errorf("CleanPath(%q) = %q, want an error", in, got)
		}
	}
}

// An exclusion of /admin holds against every spelling a server reads as it.
func TestDeniedSpellings(t *testing.T) {
	deny := []string{"/admin"}
	for _, raw := range []string{"/admin", "/Admin", "/ADMIN/x", "/%61dmin", "/x/../admin", "/admin;x", "/;/admin", "/administrator", "//admin"} {
		c, err := CleanPath(raw)
		if err != nil {
			continue // refused outright is also never sent
		}
		if _, ok := Denied(c, deny); !ok {
			t.Errorf("%q (clean %q) is not denied under /admin", raw, c)
		}
	}
	for _, raw := range []string{"/", "/public", "/ad", "/x/admin"} {
		c, _ := CleanPath(raw)
		if d, ok := Denied(c, deny); ok {
			t.Errorf("%q denied by %q", raw, d)
		}
	}
}

func TestUnder(t *testing.T) {
	cases := []struct {
		p, prefix string
		want      bool
	}{
		{"/app", "/app", true}, {"/app/x", "/app/", true}, {"/application", "/app", false},
		{"/x", "", true}, {"/x", "/", true}, {"/app;x/y", "/app", false}, {"/app/y;z", "/app", true},
	}
	for _, c := range cases {
		if got := Under(c.p, c.prefix); got != c.want {
			t.Errorf("Under(%q, %q) = %v, want %v", c.p, c.prefix, got, c.want)
		}
	}
}

func TestDestructive(t *testing.T) {
	yes := []string{
		"/logout", "/Logout", "/user/log-out", "/sign_out", "/auth/signout", "/account/logoff",
		"/admin/delete", "/api/v1/users/deleteUser", "/items/remove-all", "/db/drop", "/cache/purge",
		"/reset", "/resetPassword", "/system/shutdown", "/svc/restart", "/reboot", "/proc/kill",
		"/newsletter/unsubscribe", "/order/cancel", "/token/revoke", "/x/destroy.php", "/wipe",
		"/%6cogout", "/a/LOGOUT.aspx",
	}
	for _, p := range yes {
		if !Destructive(p) {
			t.Errorf("Destructive(%q) = false", p)
		}
	}
	no := []string{
		"/", "/index.php.bak", "/api/v2/users", "/assets/dropdown.js", "/skills", "/preset", "/login",
		"/admin", "/backup.zip", "/wiper-blades", "/killer-app", "/.git/config",
	}
	for _, p := range no {
		if Destructive(p) {
			t.Errorf("Destructive(%q) = true", p)
		}
	}
}

func FuzzCleanPath(f *testing.F) {
	for _, s := range []string{"/", "/a/../b", "/%2e%2e/x", "/a;b/..;/c", "/%c0%ae"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		c, err := CleanPath(raw)
		if err != nil {
			return
		}
		if !strings.HasPrefix(c, "/") || HasDotSegment(strings.TrimSuffix(c, "/")) || strings.ContainsFunc(c, isControl) {
			t.Fatalf("CleanPath(%q) = %q", raw, c)
		}
		// Idempotent: cleaning a clean path changes nothing.
		if c2, err := CleanPath(c); err == nil && c2 != c && !strings.Contains(c, "%") {
			t.Fatalf("CleanPath not idempotent: %q -> %q -> %q", raw, c, c2)
		}
	})
}
