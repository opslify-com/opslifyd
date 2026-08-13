package daemon

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opslify-com/opslifyd/internal/session"
)

// A gated exec surfaces a structured `pending` NDJSON frame (200, not an error)
// carrying the exec_id — never a hang, never a failure status.
func TestHTTPExecApprovalPendingFrame(t *testing.T) {
	mgr := &fakeManager{execErr: &session.ApprovalPendingError{ExecID: "ex-9", Rule: "approval_required:rm", Reason: "needs approval"}}
	d := newTestDaemon(t, mgr)
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/sessions/sess-1/exec", "application/json",
		strings.NewReader(`{"argv":["rm","-rf","/"]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (pending is not an error)", resp.StatusCode)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Scan()
	var f struct {
		Status string `json:"status"`
		ExecID string `json:"exec_id"`
		Rule   string `json:"rule"`
	}
	if err := json.Unmarshal(sc.Bytes(), &f); err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	if f.Status != "pending" || f.ExecID != "ex-9" {
		t.Fatalf("frame = %+v, want pending/ex-9", f)
	}
}

// POST resolve routes the decision+comment to the manager and returns its view.
func TestHTTPApprovalResolve(t *testing.T) {
	mgr := &fakeManager{resolveView: session.ApprovalView{SessionID: "sess-1", ExecID: "ex-1", Status: session.ApprovalApproved}}
	d := newTestDaemon(t, mgr)
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/sessions/sess-1/approvals/ex-1", "application/json",
		strings.NewReader(`{"decision":"approve","comment":"ok"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if mgr.lastResolve != [3]string{"sess-1", "ex-1", "approve"} {
		t.Fatalf("manager got resolve %v", mgr.lastResolve)
	}
}

// A resolve on an already-resolved gate maps to 409 Conflict (no-resurrection).
func TestHTTPApprovalResolveConflict(t *testing.T) {
	mgr := &fakeManager{resolveErr: session.ErrApprovalResolved}
	d := newTestDaemon(t, mgr)
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/sessions/sess-1/approvals/ex-1", "application/json",
		strings.NewReader(`{"decision":"deny"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
}

// GET /v1/approvals lists the pending queue.
func TestHTTPApprovalList(t *testing.T) {
	mgr := &fakeManager{approvals: []session.ApprovalView{{SessionID: "s", ExecID: "e", Status: session.ApprovalPending}}}
	d := newTestDaemon(t, mgr)
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()

	resp := mustGet(t, srv.URL+"/v1/approvals")
	defer resp.Body.Close()
	var list []session.ApprovalView
	json.NewDecoder(resp.Body).Decode(&list)
	if len(list) != 1 || list[0].ExecID != "e" {
		t.Fatalf("list = %+v", list)
	}
}
