package primedns

import (
	"fmt"

	"github.com/DNSControl/dnscontrol/v5/models"
	"github.com/DNSControl/dnscontrol/v5/pkg/rejectif"
)

// AuditRecords returns a list of errors corresponding to the records that PrimeDNS cannot store.
// If all records are supported, an empty list is returned.
func (*primednsProvider) AuditRecords(records models.Records) []error {
	a := rejectif.Auditor{}

	a.Add("MX", rejectif.MxNull)               // the API wants a target for MX
	a.Add("SRV", rejectif.SrvHasNullTarget)    // the API wants a target for SRV
	a.Add("TXT", rejectif.TxtIsEmpty)          // empty TXT content is rejected (EMPTY_CONTENT)
	a.Add("TXT", rejectif.TxtHasTrailingSpace) // not stored reliably
	a.Add("CAA", rejectif.CaaTargetContainsWhitespace)

	errs := a.Audit(records)
	for _, rc := range records {
		if rc.TTL < 60 || rc.TTL > 86400 {
			errs = append(errs, fmt.Errorf("%s %s: PrimeDNS TTL must be between 60 and 86400 seconds, got %d", rc.GetLabelFQDN(), rc.Type, rc.TTL))
		}
	}
	return errs
}
