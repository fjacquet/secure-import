package redfish

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Message is one @Message.ExtendedInfo entry.
type Message struct{ ID, Text, Severity, Resolution string }

type rawMessage struct {
	MessageID  string `json:"MessageId"`
	Message    string `json:"Message"`
	Severity   string `json:"Severity"`
	Resolution string `json:"Resolution"`
}

// ParseMessages extracts ExtendedInfo from a body, either at the top level or
// inside an {"error": {...}} envelope. Unparseable bodies yield no messages.
func ParseMessages(body []byte) []Message {
	var doc struct {
		Info  []rawMessage `json:"@Message.ExtendedInfo"`
		Error struct {
			Info []rawMessage `json:"@Message.ExtendedInfo"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	var out []Message
	for _, m := range append(doc.Info, doc.Error.Info...) {
		out = append(out, Message{ID: m.MessageID, Text: m.Message, Severity: m.Severity, Resolution: m.Resolution})
	}
	return out
}

// Success MessageIds vary with firmware (Base.1.0 vs Base.1.12, iDRAC.1.6 vs
// IDRAC.2.9), so they are matched by pattern, ignoring case and version.
var successPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^Base\.\d+\.\d+\.Success$`),
	regexp.MustCompile(`(?i)^i?DRAC\.\d+\.\d+\.SYS4\d+$`),
	regexp.MustCompile(`(?i)^Bios\.\d+\.\d+\.BiosPropertyModified$`),
}

// IsSuccessID reports whether a MessageId is a known success code.
func IsSuccessID(id string) bool {
	for _, re := range successPatterns {
		if re.MatchString(id) {
			return true
		}
	}
	return false
}

// IsSuccess reports whether a message is a success: its MessageId matches a known
// success pattern and its severity is not Critical. The SYS4xx pattern also matches
// error codes such as IDRAC.2.9.SYS403 ("resource not found", Critical), so the
// severity is needed to tell them apart.
func IsSuccess(m Message) bool {
	return IsSuccessID(m.ID) && !strings.EqualFold(m.Severity, "Critical")
}

// NeedsReboot reports whether any message says a restart or reboot is needed.
func NeedsReboot(msgs []Message) bool {
	for _, m := range msgs {
		s := strings.ToLower(m.Resolution + " " + m.Text)
		if strings.Contains(s, "restart") || strings.Contains(s, "reboot") {
			return true
		}
	}
	return false
}

// Summarize renders messages as "Severity: Text; Severity: Text".
func Summarize(msgs []Message) string {
	parts := make([]string, len(msgs))
	for i, m := range msgs {
		parts[i] = m.Severity + ": " + m.Text
	}
	return strings.Join(parts, "; ")
}
