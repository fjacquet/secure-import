// Package report holds per-host results and writes them as CSV or JSON.
package report

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"
	"strings"
)

// Result is the outcome of one action on one host.
type Result struct {
	IP              string `json:"ip"`
	Action          string `json:"action"`
	Platform        string `json:"platform"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	CurrentStatus   string `json:"current_status"`
	CurrentBoot     string `json:"current_boot"`
	CurrentMode     string `json:"current_mode"`
	CurrentPolicy   string `json:"current_policy"`
	NewPolicy       string `json:"new_policy"`
	CertificatesURI string `json:"certificates_uri"`
	NewStatus       string `json:"new_status"`
	Success         bool   `json:"success"`
	ChangeMessage   string `json:"change_message"`
	Message         string `json:"message"`
	Error           string `json:"error"`
	CertCount       int    `json:"certificate_count"`
}

// New returns a Result carrying the same defaults as the Python script.
func New(ip, action, platform string) Result {
	return Result{
		IP: ip, Action: action, Platform: platform,
		Name: "Unknown", CurrentStatus: "Unknown", CurrentBoot: "Unknown", CurrentMode: "Unknown",
		CurrentPolicy: "Unknown", NewPolicy: "Unknown", CertificatesURI: "N/A", NewStatus: "Unknown",
	}
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// WriteCSV writes results with the Python column layout (DB layout for db_*
// actions) plus a final Platform column.
func WriteCSV(w io.Writer, action string, results []Result) error {
	cw := csv.NewWriter(w)
	if strings.HasPrefix(action, "db_") {
		_ = cw.Write([]string{"IP Address", "Action", "Success", "Message", "Error", "Certificate Count", "Platform"})
		for _, r := range results {
			_ = cw.Write([]string{r.IP, r.Action, yesNo(r.Success), r.Message, r.Error, strconv.Itoa(r.CertCount), r.Platform})
		}
	} else {
		_ = cw.Write([]string{"IP Address", "Action", "Name", "Description", "Current Status", "Current Boot",
			"Current Mode", "Current Policy", "New Policy", "Certificates URI", "New Status", "Success",
			"Change Message", "Error", "Platform"})
		for _, r := range results {
			_ = cw.Write([]string{r.IP, r.Action, r.Name, r.Description, r.CurrentStatus, r.CurrentBoot,
				r.CurrentMode, r.CurrentPolicy, r.NewPolicy, r.CertificatesURI, r.NewStatus, yesNo(r.Success),
				r.ChangeMessage, r.Error, r.Platform})
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteJSON writes results as an indented JSON array.
func WriteJSON(w io.Writer, results []Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}
