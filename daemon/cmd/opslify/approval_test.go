package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// `opslify approvals` renders the pending queue as a table.
func TestApprovalsListTable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/approvals", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]approvalView{
			{SessionID: "sess-1", ExecID: "ex-1", Rule: "approval_required:kubectl delete", ArgvSummary: "kubectl delete pod x"},
		})
	})
	f := newFakeDaemon(t, mux)

	out, _, err := execRoot(t, "approvals", "--socket", f.socketPath)
	if err != nil {
		t.Fatalf("approvals: %v", err)
	}
	if !strings.Contains(out, "ex-1") || !strings.Contains(out, "kubectl delete pod x") {
		t.Fatalf("table missing pending gate:\n%s", out)
	}
}

// `opslify approve` POSTs the decision+comment and reports the resolved status.
func TestApproveCommand(t *testing.T) {
	var gotBody string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions/{id}/approvals/{exec_id}", func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		r.Body.Read(b)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(approvalView{SessionID: r.PathValue("id"), ExecID: r.PathValue("exec_id"), Status: "approved"})
	})
	f := newFakeDaemon(t, mux)

	out, _, err := execRoot(t, "approve", "sess-1", "ex-1", "--comment", "ok by SRE", "--socket", f.socketPath)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if !strings.Contains(gotBody, `"decision":"approve"`) || !strings.Contains(gotBody, "ok by SRE") {
		t.Fatalf("posted body = %s", gotBody)
	}
	if !strings.Contains(out, "approved sess-1/ex-1") {
		t.Fatalf("output = %s", out)
	}
}

// `opslify deny` posts a deny decision.
func TestDenyCommand(t *testing.T) {
	var gotBody string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions/{id}/approvals/{exec_id}", func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		r.Body.Read(b)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(approvalView{SessionID: r.PathValue("id"), ExecID: r.PathValue("exec_id"), Status: "denied"})
	})
	f := newFakeDaemon(t, mux)

	out, _, err := execRoot(t, "deny", "sess-1", "ex-1", "--socket", f.socketPath)
	if err != nil {
		t.Fatalf("deny: %v", err)
	}
	if !strings.Contains(gotBody, `"decision":"deny"`) {
		t.Fatalf("posted body = %s", gotBody)
	}
	if !strings.Contains(out, "denied sess-1/ex-1") {
		t.Fatalf("output = %s", out)
	}
}
