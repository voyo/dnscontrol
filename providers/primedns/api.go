package primedns

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBaseURL = "https://api.primedns.net/v1"
	maxAttempts    = 4
	maxRetryWait   = 60 * time.Second
)

// zone is a zone ("domain") of the PrimeDNS account.
type zone struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// record is a PrimeDNS DNS record as returned by GET /dns/records.
type record struct {
	ID       int    `json:"id"`
	DomainID int    `json:"domain_id"`
	Name     string `json:"name"` // always the FQDN, without a trailing dot
	Type     string `json:"type"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Prio     *int   `json:"prio"` // MX and SRV priority; null for the other types
}

// recordInput is the body of POST /dns/records and PATCH /dns/records/{id}.
type recordInput struct {
	DomainID int    `json:"domain_id,omitempty"` // create only
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Prio     *int   `json:"prio,omitempty"`
}

type apiEnvelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// apiError is an error answer of the PrimeDNS API.
type apiError struct {
	Status  int
	Code    string
	Message string
}

func (e *apiError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("PrimeDNS API HTTP %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("PrimeDNS API HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

// do sends a request and decodes the "data" part of the answer into out (when out is not nil).
// It retries once the API says "slow down" (429) or is temporarily unavailable (502, 503, 504).
func (p *primednsProvider) do(method, path string, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return fmt.Errorf("encoding the request: %w", err)
		}
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequest(method, p.baseURL+path, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("X-API-Key", p.apiKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "dnscontrol")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := p.client.Do(req)
		if err != nil {
			return fmt.Errorf("PrimeDNS API request failed: %w", err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("reading the PrimeDNS API answer: %w", readErr)
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if out == nil {
				return nil
			}
			var env apiEnvelope
			if err := json.Unmarshal(raw, &env); err != nil {
				return fmt.Errorf("decoding the PrimeDNS API answer: %w", err)
			}
			if err := json.Unmarshal(env.Data, out); err != nil {
				return fmt.Errorf("decoding the PrimeDNS API data: %w", err)
			}
			return nil
		}

		lastErr = parseAPIError(resp.StatusCode, raw)
		retryable := resp.StatusCode == 429 || resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504
		if !retryable || attempt == maxAttempts {
			return lastErr
		}
		time.Sleep(retryWait(resp.Header.Get("Retry-After"), attempt))
	}
	return lastErr
}

func parseAPIError(status int, raw []byte) error {
	var env apiEnvelope
	_ = json.Unmarshal(raw, &env)
	e := &apiError{Status: status, Code: env.Error.Code, Message: env.Error.Message}
	if e.Message == "" {
		e.Message = strings.TrimSpace(string(raw))
		if len(e.Message) > 200 {
			e.Message = e.Message[:200]
		}
	}
	if status == 401 {
		e.Message += " (check api_key)"
	}
	return e
}

// retryWait returns how long to wait: the Retry-After seconds when given (at most a minute), else 2, 4, 8 ... seconds.
func retryWait(header string, attempt int) time.Duration {
	if n, err := strconv.Atoi(strings.TrimSpace(header)); err == nil && n >= 0 {
		d := time.Duration(n) * time.Second
		if d > maxRetryWait {
			d = maxRetryWait
		}
		return d
	}
	return time.Duration(1<<uint(attempt)) * time.Second
}

func (p *primednsProvider) listZones() ([]zone, error) {
	var out struct {
		Domains []zone `json:"domains"`
	}
	if err := p.do(http.MethodGet, "/domains", nil, &out); err != nil {
		return nil, err
	}
	return out.Domains, nil
}

func (p *primednsProvider) getZone(name string) (*zone, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	zones, err := p.listZones()
	if err != nil {
		return nil, err
	}
	for i := range zones {
		if strings.ToLower(strings.TrimSuffix(zones[i].Name, ".")) == name {
			return &zones[i], nil
		}
	}
	return nil, errZoneNotFound
}

var errZoneNotFound = errors.New("zone not found in this PrimeDNS account")

func (p *primednsProvider) createZone(name string) error {
	return p.do(http.MethodPost, "/domains/external", map[string]string{"domain": name}, nil)
}

func (p *primednsProvider) listRecords(domain string) ([]record, error) {
	var out struct {
		Records []record `json:"records"`
	}
	if err := p.do(http.MethodGet, "/dns/records?domain="+domain, nil, &out); err != nil {
		return nil, err
	}
	return out.Records, nil
}

func (p *primednsProvider) createRecord(in recordInput) error {
	return p.do(http.MethodPost, "/dns/records", in, nil)
}

func (p *primednsProvider) updateRecord(id int, in recordInput) error {
	return p.do(http.MethodPatch, "/dns/records/"+strconv.Itoa(id), in, nil)
}

func (p *primednsProvider) deleteRecord(id int) error {
	return p.do(http.MethodDelete, "/dns/records/"+strconv.Itoa(id), nil, nil)
}
