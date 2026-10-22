package core

import (
	"net"
	"strings"
)

// Identities are shared by discovery, direct queries, and investigation replay.
func WorkloadIdentity(w WorkloadRef) string { return w.Namespace + "/" + w.Kind + "/" + w.Name }

func PeerIdentity(q PeerQuery) string {
	switch q.Kind {
	case "workload":
		if strings.Contains(q.Value, "/") {
			return q.Namespace + "/" + q.Value
		}
		return q.Namespace + "/workload/" + q.Value
	case "service":
		return q.Value + "." + q.Namespace + ".svc.cluster.local"
	case "ip":
		return "ip:" + q.Value
	default:
		return strings.TrimSuffix(q.Value, ".")
	}
}

func PeerFromConnection(c Connection, direction string) *PeerQuery {
	value := c.Destination
	if direction == "inbound" {
		value = c.Source
	}
	q := &PeerQuery{Kind: "host", Value: value, Port: c.Port, Protocol: c.Protocol}
	ip := strings.TrimPrefix(value, "ip:")
	if parsed := net.ParseIP(ip); parsed != nil {
		q.Kind, q.Value = "ip", parsed.String()
	} else if parts := strings.Split(value, "/"); len(parts) == 3 {
		q.Kind, q.Namespace, q.Value = "workload", parts[0], parts[1]+"/"+parts[2]
		if parts[1] == "workload" {
			q.Value = parts[2]
		}
	}
	return q
}

// Missing direct-query port/protocol are constraints left open, never zero-valued
// observed ports. Queue selections contain concrete metadata and match exactly.
func ConnectionMatches(observed, selected Connection) bool {
	return observed.Source == selected.Source && observed.Destination == selected.Destination &&
		(selected.Port == 0 || observed.Port == selected.Port) &&
		(selected.Protocol == "" || selected.Protocol == "unknown" || observed.Protocol == selected.Protocol)
}
