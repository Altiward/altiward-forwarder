package ocsf

import (
	"fmt"
	"strings"
)

// cefSeverity maps OCSF severity onto CEF's 0–10 scale, as the server does.
var cefSeverity = map[int]int{1: 1, 2: 3, 3: 5, 4: 8}

// CEF renders a record as one line:
//
//	CEF:0|Altiward|Altiward Forwarder|<version>|<event type>|<type name>|<severity>|<extensions>
//
// The extensions and custom-string slots mean what they mean in the server's CEF (cs1
// tenant, cs3 reason, cs4 source, cs6 event type), so SIEM parsing works for both.
func CEF(r Record) string {
	version := Str(r, "metadata", "product", "version")
	if version == "" {
		version = "0"
	}
	host := Str(r, "device", "hw_info", "serial_number")
	if host == "" {
		host = Str(r, "device", "uid")
	}

	var ext []string
	add := func(key, value string) {
		if value != "" {
			ext = append(ext, key+"="+cefValue(value))
		}
	}
	custom := func(n int, label, value string) {
		if value != "" {
			add(fmt.Sprintf("cs%dLabel", n), label)
			add(fmt.Sprintf("cs%d", n), value)
		}
	}
	add("rt", fmt.Sprint(Int(r, "time")))
	add("externalId", Str(r, "metadata", "uid"))
	add("cat", Str(r, "class_name"))
	add("act", Str(r, "activity_name"))
	add("outcome", Str(r, "status"))
	add("dvchost", host)
	add("deviceExternalId", Str(r, "device", "uid"))
	add("duser", Str(r, "user", "name"))
	add("msg", Str(r, "message"))
	custom(1, "tenant", Str(r, "metadata", "tenant_uid"))
	custom(3, "reason", Str(r, "unmapped", "altiward", "reason"))
	custom(4, "source", Str(r, "unmapped", "altiward", "source"))
	custom(6, "eventType", Str(r, "unmapped", "altiward", "event_type"))

	return fmt.Sprintf("CEF:0|Altiward|Altiward Forwarder|%s|%s|%s|%d|%s",
		cefHeader(version), cefHeader(Str(r, "unmapped", "altiward", "event_type")), cefHeader(Str(r, "type_name")),
		cefSeverity[Int(r, "severity_id")], strings.Join(ext, " "))
}

var (
	headerEscaper = strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\r", " ", "\n", " ")
	valueEscaper  = strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\r", `\r`, "\n", `\n`)
)

// cefHeader escapes a header field; a header can't hold a line break, so it becomes a space.
func cefHeader(s string) string { return headerEscaper.Replace(s) }

// cefValue escapes an extension value.
func cefValue(s string) string { return valueEscaper.Replace(s) }
