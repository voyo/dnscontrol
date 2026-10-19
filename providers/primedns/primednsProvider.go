package primedns

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/DNSControl/dnscontrol/v5/models"
	"github.com/DNSControl/dnscontrol/v5/pkg/diff2"
	"github.com/DNSControl/dnscontrol/v5/pkg/providers"
)

/*

PrimeDNS (https://primedns.net) DNS provider.

Info required in `creds.json`:
   - api_key   A PrimeDNS API key (X-API-Key). It needs the scopes dns:read, dns:write and domains:read,
               and zones:create to let "dnscontrol create-zones" add a zone.
Optional:
   - api_url   The API base URL. Default https://api.primedns.net/v1

*/

func init() {
	providers.Register[*primednsProvider]("PRIMEDNS", providers.Definition{
		FriendlyName: "PrimeDNS",
		Maintainer:   "@voyo",
		SupportedTypes: []string{
			"Basic8",
			"ALIAS",
			"DNAME",
			"DS",
			"HTTPS",
			"LOC",
			"NAPTR",
			"OPENPGPKEY",
			"PTR",
			"SSHFP",
			"SVCB",
			"TLSA",
		},
		// The API allows 60 requests per minute per account unless the key says otherwise.
		CanConcur: providers.Cannot(),
		CredFields: []providers.CredsField{
			{
				Key:      "api_key",
				Label:    "API key",
				Help:     "A PrimeDNS API key with the scopes dns:read, dns:write and domains:read (and zones:create to let create-zones add a zone).",
				Secret:   true,
				Required: true,
			},
			{
				Key:   "api_url",
				Label: "API URL",
				Help:  "The API base URL. Leave empty for https://api.primedns.net/v1.",
			},
		},
		PortalURL: "https://primedns.net/",
	})
}

// primednsProvider is the PrimeDNS DNSServiceProvider.
type primednsProvider struct {
	client  *http.Client
	apiKey  string
	baseURL string
}

// Initialize initializes a fresh provider instance.
func (p *primednsProvider) Initialize(m map[string]string, _ json.RawMessage, _ *providers.CreateOptions) error {
	apiKey := m["api_key"]
	if apiKey == "" {
		return errors.New("missing PrimeDNS api_key")
	}
	baseURL := strings.TrimRight(m["api_url"], "/")
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	*p = primednsProvider{
		client:  &http.Client{Timeout: 60 * time.Second},
		apiKey:  apiKey,
		baseURL: baseURL,
	}
	// Check the key right away, so a wrong key fails here and not in the middle of a run.
	if _, err := p.listZones(); err != nil {
		return fmt.Errorf("PrimeDNS credentials check failed: %w", err)
	}
	return nil
}

// GetNameservers returns no nameservers: PrimeDNS manages the apex NS records itself. Delegation at the
// registrar is done with NAMESERVER("ns1.primedns.net") and NAMESERVER("ns2.primedns.net") if you want it automated.
func (p *primednsProvider) GetNameservers(string) ([]*models.Nameserver, error) {
	return nil, nil
}

// ListZones returns the zones of the account (used by "dnscontrol get-zones").
func (p *primednsProvider) ListZones() ([]string, error) {
	zones, err := p.listZones()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(zones))
	for _, z := range zones {
		names = append(names, strings.TrimSuffix(z.Name, "."))
	}
	return names, nil
}

// EnsureZoneExists adds the zone to the account when it is missing.
func (p *primednsProvider) EnsureZoneExists(dc *models.DomainConfig) error {
	if _, err := p.getZone(dc.Name); err == nil {
		return nil
	} else if !errors.Is(err, errZoneNotFound) {
		return err
	}
	return p.createZone(dc.Name)
}

// GetZoneRecords returns the records of the zone.
func (p *primednsProvider) GetZoneRecords(dc *models.DomainConfig) (models.Records, error) {
	if _, err := p.getZone(dc.Name); err != nil {
		return nil, fmt.Errorf("zone %s: %w", dc.Name, err)
	}
	records, err := p.listRecords(dc.Name)
	if err != nil {
		return nil, fmt.Errorf("listing the records of %s: %w", dc.Name, err)
	}

	cur := make(models.Records, 0, len(records))
	for _, r := range records {
		if skipRecord(dc.Name, r) {
			continue
		}
		rc, err := toRecordConfig(dc, r)
		if err != nil {
			return nil, fmt.Errorf("record %s %s: %w", r.Name, r.Type, err)
		}
		cur = append(cur, rc)
	}
	return cur, nil
}

// GetZoneRecordsCorrections returns the changes that turn curRecords into the desired records of dc.
func (p *primednsProvider) GetZoneRecordsCorrections(dc *models.DomainConfig, curRecords models.Records) ([]*models.Correction, int, error) {
	z, err := p.getZone(dc.Name)
	if err != nil {
		return nil, 0, fmt.Errorf("zone %s: %w", dc.Name, err)
	}

	changes, actualChangeCount, err := diff2.ByRecord(curRecords, dc, nil)
	if err != nil {
		return nil, 0, err
	}

	var corrections []*models.Correction
	for _, change := range changes {
		switch change.Type {
		case diff2.REPORT:
			corrections = append(corrections, &models.Correction{Msg: change.MsgsJoined})
		case diff2.CREATE:
			in := fromRecordConfig(change.New[0])
			in.DomainID = z.ID
			corrections = append(corrections, &models.Correction{
				Msg: change.Msgs[0],
				F:   func() error { return p.createRecord(in) },
			})
		case diff2.CHANGE:
			old := change.Old[0].Original.(record)
			in := fromRecordConfig(change.New[0])
			corrections = append(corrections, &models.Correction{
				Msg: fmt.Sprintf("%s; PrimeDNS record id %d", change.Msgs[0], old.ID),
				F:   func() error { return p.updateRecord(old.ID, in) },
			})
		case diff2.DELETE:
			old := change.Old[0].Original.(record)
			corrections = append(corrections, &models.Correction{
				Msg: fmt.Sprintf("%s; PrimeDNS record id %d", change.Msgs[0], old.ID),
				F:   func() error { return p.deleteRecord(old.ID) },
			})
		default:
			panic(fmt.Sprintf("unhandled change.Type %s", change.Type))
		}
	}
	return corrections, actualChangeCount, nil
}
