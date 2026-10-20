// Package sink sends OCSF records to a SIEM, shaped as the Altiward server sends them, so
// both land in the same index, table or syslog feed. The transports come from the
// integrations module in the main Altiward repository.
package sink

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/Altiward/altiward/integrations/sentinel"
	"github.com/Altiward/altiward/integrations/splunk"
	"github.com/Altiward/altiward/integrations/syslog"

	"github.com/Altiward/altiward-forwarder/internal/ocsf"
)

// Sink is one destination. Send returns nil only when the destination accepted every record.
type Sink interface {
	Name() string // also the name of the sink's spool directory
	Send(ctx context.Context, records []ocsf.Record) error
}

func recordTime(r ocsf.Record) time.Time { return time.UnixMilli(int64(ocsf.Int(r, "time"))).UTC() }

// host names the Mac: its serial when known (the hook), else its hardware UUID.
func host(r ocsf.Record) string {
	if s := ocsf.Str(r, "device", "hw_info", "serial_number"); s != "" {
		return s
	}
	return ocsf.Str(r, "device", "uid")
}

// Splunk sends each record as one HEC event with the server's sourcetype, altiward:ocsf.
type Splunk struct {
	Client *splunk.Client
	Index  string
}

func (s *Splunk) Name() string { return "splunk" }

func (s *Splunk) Send(ctx context.Context, records []ocsf.Record) error {
	events := make([]splunk.Event, 0, len(records))
	for _, r := range records {
		events = append(events, splunk.Event{
			Time:       float64(ocsf.Int(r, "time")) / 1000,
			Host:       host(r),
			Source:     "altiward-forwarder",
			SourceType: "altiward:ocsf",
			Index:      s.Index,
			Event:      r,
		})
	}
	return s.Client.Send(ctx, events)
}

// Sentinel uploads rows for the AltiwardOCSF_CL table, the one the server writes to.
type Sentinel struct{ Client *sentinel.Client }

func (s *Sentinel) Name() string { return "sentinel" }

func (s *Sentinel) Send(ctx context.Context, records []ocsf.Record) error {
	rows := make([]any, 0, len(records))
	for _, r := range records {
		rows = append(rows, sentinel.Row{
			TimeGenerated: recordTime(r),
			EventUid:      ocsf.Str(r, "metadata", "uid"),
			TenantUid:     ocsf.Str(r, "metadata", "tenant_uid"),
			ClassUid:      ocsf.Int(r, "class_uid"),
			ActivityId:    ocsf.Int(r, "activity_id"),
			SeverityId:    ocsf.Int(r, "severity_id"),
			DeviceSerial:  ocsf.Str(r, "device", "hw_info", "serial_number"),
			UserName:      ocsf.Str(r, "user", "name"),
			Message:       ocsf.Str(r, "message"),
			Ocsf:          r,
		})
	}
	return s.Client.Upload(ctx, rows)
}

// Syslog sends each record as one RFC 5424 message: facility authpriv, the event type as
// MSGID, and a CEF ("cef") or OCSF JSON ("json") body.
type Syslog struct {
	Client *syslog.Client
	Format string
}

func (s *Syslog) Name() string { return "syslog" }

func (s *Syslog) Send(ctx context.Context, records []ocsf.Record) error {
	msgs := make([]syslog.Message, 0, len(records))
	for _, r := range records {
		body := ocsf.CEF(r)
		if s.Format == "json" {
			b, err := json.Marshal(r)
			if err != nil {
				return fmt.Errorf("syslog: encode record: %w", err)
			}
			body = string(b)
		}
		msgs = append(msgs, syslog.Message{
			Time: recordTime(r), Facility: syslog.FacilityAuthPriv, Severity: syslog.SeverityInfo,
			Hostname: "altiward-forwarder", AppName: "altiward-forwarder",
			MsgID: ocsf.Str(r, "unmapped", "altiward", "event_type"), Body: body,
		})
	}
	return s.Client.Send(ctx, msgs)
}

// Stdout writes one compact JSON record per line, for a container log or a quick look.
type Stdout struct{ W io.Writer }

func (s *Stdout) Name() string { return "stdout" }

func (s *Stdout) Send(ctx context.Context, records []ocsf.Record) error {
	enc := json.NewEncoder(s.W)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}
