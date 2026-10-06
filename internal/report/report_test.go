package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteCSVSecureBootColumnsMatchPython(t *testing.T) {
	r := New("10.0.0.1", "status", "idrac9")
	r.Success, r.Name, r.CurrentStatus, r.NewStatus = true, "Sec", "Enabled", "Enabled"
	var buf bytes.Buffer
	if err := WriteCSV(&buf, "status", []Result{r}); err != nil {
		t.Fatal(err)
	}
	want := "IP Address,Action,Name,Description,Current Status,Current Boot,Current Mode,Current Policy,New Policy,Certificates URI,New Status,Success,Change Message,Error,Platform\n" +
		"10.0.0.1,status,Sec,,Enabled,Unknown,Unknown,Unknown,Unknown,N/A,Enabled,Yes,,,idrac9\n"
	if buf.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestWriteCSVDBColumnsAndQuoting(t *testing.T) {
	r := New("10.0.0.2", "db_list", "ilo")
	r.Success, r.Message, r.CertCount = true, "Found 2, ok", 2
	f := New("10.0.0.3", "db_list", "")
	f.Error = "HTTP 401: nope"
	var buf bytes.Buffer
	if err := WriteCSV(&buf, "db_list", []Result{r, f}); err != nil {
		t.Fatal(err)
	}
	want := "IP Address,Action,Success,Message,Error,Certificate Count,Platform\n" +
		`10.0.0.2,db_list,Yes,"Found 2, ok",,2,ilo` + "\n" +
		"10.0.0.3,db_list,No,,HTTP 401: nope,0,\n"
	if buf.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestWriteJSONRoundTripsAndNeverEmitsPasswords(t *testing.T) {
	r := New("10.0.0.1", "status", "lenovo")
	r.Success = true
	var buf bytes.Buffer
	if err := WriteJSON(&buf, []Result{r}); err != nil {
		t.Fatal(err)
	}
	var back []Result
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil || len(back) != 1 || back[0].IP != "10.0.0.1" || !back[0].Success {
		t.Fatalf("round trip failed: %v %+v", err, back)
	}
	if strings.Contains(strings.ToLower(buf.String()), "password") {
		t.Error("JSON output must not contain a password field")
	}
}

func TestWriteCSVNeutralisesFormulaCells(t *testing.T) {
	r := New("10.0.0.3", "db_list", "ilo")
	r.Error = "=HYPERLINK(\"http://x\")"
	r.Message = "+cmd"
	var buf bytes.Buffer
	if err := WriteCSV(&buf, "db_list", []Result{r}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), ",=HYPERLINK") || strings.Contains(buf.String(), ",+cmd") || !strings.Contains(buf.String(), "'=HYPERLINK") {
		t.Errorf("csv = %q", buf.String())
	}
}

func TestWriteCSVNeutralisesBMCFields(t *testing.T) {
	evil := "=HYPERLINK(\"http://evil/\",\"x\")"
	r := Result{IP: "10.0.0.1", Action: "status", Name: evil, Description: "+cmd", CurrentStatus: "@x",
		CurrentBoot: "-1", CurrentMode: "\t=1", CurrentPolicy: "\r=1", NewPolicy: evil,
		CertificatesURI: evil, NewStatus: evil, Platform: "idrac9"}
	var b bytes.Buffer
	if err := WriteCSV(&b, "status", []Result{r}); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&b).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range rows[1] {
		if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
			t.Errorf("column %q starts with a formula character: %q", rows[0][i], v)
		}
	}
}
