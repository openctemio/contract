package webpath

import "testing"

// denied cleans raw as a request and checks it against deny.
func denied(t *testing.T, raw string, deny ...string) bool {
	t.Helper()
	c, err := CleanPath(raw)
	if err != nil {
		return true // refused outright is never sent
	}
	_, ok := Denied(c, deny)
	return ok
}

func TestDeniedPercentEncodedDeny(t *testing.T) {
	for _, d := range []string{"/files/My%20Docs", "/files/My Docs", "/files/my%20docs"} {
		for _, raw := range []string{"/files/My%20Docs/a.bak", "/files/My Docs/a.bak", "/FILES/my%20docs"} {
			if !denied(t, raw, d) {
				t.Errorf("%q is not denied by %q", raw, d)
			}
		}
		if denied(t, "/files/other", d) {
			t.Errorf("/files/other denied by %q", d)
		}
	}
	// A deny path stored decoded that still holds an escape is also read
	// as written: "/x/100%41" (from "/x/100%2541") denies both readings.
	for _, raw := range []string{"/x/100%2541/y", "/x/100A/y"} {
		if !denied(t, raw, "/x/100%41") {
			t.Errorf("%q is not denied by /x/100%%41", raw)
		}
	}
}

func TestDeniedWildcardSegment(t *testing.T) {
	deny := "/tenants/*/admin"
	for _, raw := range []string{"/tenants/acme/admin", "/tenants/acme/admin/x", "/Tenants/ACME/Admin", "/tenants/acme/administrator",
		"/tenants/a/x/../admin/y", "/tenants/%61cme/%61dmin"} {
		if !denied(t, raw, deny) {
			t.Errorf("%q is not denied by %q", raw, deny)
		}
	}
	for _, raw := range []string{"/tenants", "/tenants/acme", "/tenants/acme/users", "/tenants/admin", "/x/tenants/acme/admin"} {
		if denied(t, raw, deny) {
			t.Errorf("%q denied by %q", raw, deny)
		}
	}
	if !denied(t, "/a/b/c/d", "/a/*/*/d") || denied(t, "/a/b/d", "/a/*/*/d") {
		t.Error("two wildcard segments")
	}
	if !denied(t, "/api/v1/", "/api/*/") || denied(t, "/api/v1", "/api/*/") {
		t.Error("wildcard with a trailing slash")
	}
}

// Spellings a lenient server reads as a denied path.
func TestDeniedServerSpecificSpellings(t *testing.T) {
	cases := map[string]string{
		"/x/%252e%252e/admin": "/admin",  // decoded twice
		"/%2561dmin/x":        "/admin",  // decoded twice
		"/%C5%BFecret":        "/secret", // U+017F folds to s
		"/%E2%84%AAibana":     "/kibana", // U+212A folds to k
		"/%C4%B1nternal":      "/internal",
		"/admin./x":           "/admin/", // trailing dot dropped
		"/admin.%20/x":        "/admin/",
		"/admin%20/x":         "/admin/",
		"/tenants/a./admin":   "/tenants/*/admin",
		"/tenants/a/admin..":  "/tenants/*/admin",
	}
	for raw, d := range cases {
		if !denied(t, raw, d) {
			t.Errorf("%q is not denied by %q", raw, d)
		}
	}
	// A deny path written with a trailing dot holds too.
	if !denied(t, "/admin/x", "/admin./") {
		t.Error("deny /admin./ does not hold for /admin/x")
	}
}

func TestDeniedKeepsPlainPaths(t *testing.T) {
	for _, raw := range []string{"/", "/public", "/.well-known/security.txt", "/a.b/c", "/x/admin", "/s3cret"} {
		if denied(t, raw, "/admin", "/secret", "/tenants/*/admin") {
			t.Errorf("%q denied", raw)
		}
	}
}

func TestCleanDeny(t *testing.T) {
	ok := map[string]string{
		"/files/My%20Docs": "/files/My Docs",
		"/admin/":          "/admin/",
		"//a///b":          "/a/b",
		"/tenants/*/admin": "/tenants/*/admin",
		"/%61dmin":         "/admin",
	}
	for in, want := range ok {
		if got, err := CleanDeny(in); err != nil || got != want {
			t.Errorf("CleanDeny(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "admin", "/a%2fb", "/a%zz", "/x/%2e%2e/admin", "/x/../admin", "/a%00"} {
		if got, err := CleanDeny(in); err == nil {
			t.Errorf("CleanDeny(%q) = %q, want an error", in, got)
		}
	}
}

func TestCheckCandidate(t *testing.T) {
	for _, in := range []string{"/admin", "/backup.zip", "/a%20b", "/.git/config", "/api/v1/"} {
		if err := CheckCandidate(in); err != nil {
			t.Errorf("CheckCandidate(%q) = %v", in, err)
		}
	}
	for _, in := range []string{"/%252e%252e/admin", "/%25", "/%C5%BFecret", "/ſecret", "/a%2fb", "/a%zz", "/x\x01"} {
		if err := CheckCandidate(in); err == nil {
			t.Errorf("CheckCandidate(%q) = nil, want an error", in)
		}
	}
}

func FuzzDeniedDecodedDeny(f *testing.F) {
	f.Add("/files/My%20Docs", "/a.bak")
	f.Add("/tenants/*/admin", "/x")
	f.Fuzz(func(t *testing.T, d, tail string) {
		clean, err := CleanDeny(d)
		if err != nil {
			return
		}
		// A request for the deny path itself, escaped or not, is denied
		// whichever form the deny list holds.
		for _, deny := range []string{d, clean} {
			if _, ok := Denied(clean, []string{deny}); !ok && !hasWildSegment(clean) {
				t.Fatalf("Denied(%q, %q) = false", clean, deny)
			}
		}
		_ = tail
	})
}
