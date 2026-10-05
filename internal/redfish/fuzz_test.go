package redfish

import "testing"

// FuzzParseMessages: BMC bodies are untrusted, so parsing must never panic, and the
// helpers that read the result must cope with whatever comes out.
func FuzzParseMessages(f *testing.F) {
	for _, seed := range []string{
		``, `{}`, `null`, `[]`, `{"error":{"@Message.ExtendedInfo":[{"MessageId":"Base.1.0.Success","Severity":"OK"}]}}`,
		`{"@Message.ExtendedInfo":[{"MessageId":"IDRAC.2.9.SYS403","Severity":"Critical","Message":"x"}]}`,
		`{"@Message.ExtendedInfo":"not a list"}`, `{"@Message.ExtendedInfo":[null,1,"a",{}]}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		msgs := ParseMessages(body)
		_ = Summarize(msgs)
		_ = NeedsReboot(msgs)
		for _, m := range msgs {
			_ = IsSuccess(m)
		}
		if m, bad := FirstCritical(msgs); bad && m.Severity == "" {
			t.Errorf("a critical message must carry its severity: %+v", m)
		}
	})
}
