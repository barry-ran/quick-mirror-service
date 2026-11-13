//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barry-ran/quick-mirror-service/internal/binding"
	"github.com/barry-ran/quick-mirror-service/internal/catalog"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
)

func TestBindingHTTPActualDatabaseAndTLS(t *testing.T) {
	ctx := context.Background()
	pool := testHTTPPool(t)
	store, e := binding.NewStore(pool, scope, scope)
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	directory, e := catalog.NewStore(pool, scope, scope)
	if e != nil {
		t.Fatal(e)
	}
	if e = directory.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	pcPrincipal := identity.Principal{DeviceID: pc, ApplicationID: pc, TenantID: scope, Role: identity.PC}
	mobilePrincipal := identity.Principal{DeviceID: mobile, ApplicationID: mobile, TenantID: scope, Role: identity.Mobile}
	verifier := accessFunc(func(_ context.Context, credential string) (identity.Principal, error) {
		switch credential {
		case "pc-installation":
			return pcPrincipal, nil
		case "phone-installation":
			return mobilePrincipal, nil
		default:
			return identity.Principal{}, identity.ErrInvalidCredential
		}
	})
	handler, e := NewBindingHandler(verifier, store, directory, unknownPresence{}, scope, 8)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client := server.Client()
	call := func(method, path, credential, key string, body any, want int, out any) {
		t.Helper()
		var encoded []byte
		if body != nil {
			encoded, _ = json.Marshal(body)
		}
		r, e := http.NewRequest(method, server.URL+path, bytes.NewReader(encoded))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Authorization", "Bearer "+credential)
		r.Header.Set("Content-Type", "application/json")
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		resp, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		data, e := io.ReadAll(io.LimitReader(resp.Body, 65536))
		if e != nil {
			t.Fatal(e)
		}
		if resp.StatusCode != want {
			t.Fatalf("%s %s got %d want %d", method, path, resp.StatusCode, want)
		}
		if out != nil {
			var env struct {
				Data json.RawMessage `json:"data"`
			}
			if json.Unmarshal(data, &env) != nil || json.Unmarshal(env.Data, out) != nil {
				t.Fatal("invalid response shape")
			}
		}
	}
	var pcCode, phoneCode binding.Code
	call("POST", "/qm/v1/installations/self/ensure", "pc-installation", "", map[string]any{}, 200, &pcCode)
	call("POST", "/qm/v1/installations/self/ensure", "phone-installation", "", map[string]any{}, 200, &phoneCode)
	if !binding.ValidCode(pcCode.Code) || !binding.ValidCode(phoneCode.Code) {
		t.Fatal("bad code format")
	}
	var relation binding.Relation
	call("POST", "/qm/v1/bindings", "phone-installation", "fixture-bind-key", map[string]any{"code": pcCode.Code}, 200, &relation)
	if relation.PCID != pc || relation.MobileID != mobile || !relation.Active {
		t.Fatal("wrong direction")
	}
	var code binding.Code
	call("GET", "/qm/v1/binding-code/self", "phone-installation", "", nil, 200, &code)
	if code.Code != "" || !code.Bound || code.Binding == nil {
		t.Fatal("bound phone leaked addable code")
	}
	call("POST", "/qm/v1/binding-code/self/refresh", "phone-installation", "fixture-refresh-key", map[string]any{}, 409, nil)
	var listed struct {
		Items []bindingView `json:"items"`
	}
	call("GET", "/qm/v1/bindings", "pc-installation", "", nil, 200, &listed)
	if len(listed.Items) != 1 || listed.Items[0].Peer.Online != nil {
		t.Fatal("upstream failure fabricated offline/empty")
	}
	var revoked binding.Relation
	call("POST", "/qm/v1/bindings/"+relation.ID+"/unbind", "pc-installation", "fixture-unbind-key", map[string]any{"expected_revision": relation.Revision}, 200, &revoked)
	if revoked.Active || !revoked.ClosePending {
		t.Fatal("unbind authorization not revoked")
	}
	call("GET", "/qm/v1/binding-code/self", "phone-installation", "", nil, 200, &code)
	if code.Code != phoneCode.Code || code.Bound {
		t.Fatal("unbind replaced permanent phone code")
	}
	call("POST", "/qm/v1/installations/self/ensure", "invalid", "", map[string]any{}, 401, nil)
}
