// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package http_probes

import (
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/platform"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

type onionLocation struct {
	name   string
	log    *slog.Logger
	source *et.Source
}

func NewOnionLocation() et.Plugin {
	return &onionLocation{
		name: "Onion-Location",
		source: &et.Source{
			Name:       "Onion-Location",
			Confidence: 100,
		},
	}
}

func (ol *onionLocation) Name() string {
	return ol.name
}

func (ol *onionLocation) Start(r et.Registry) error {
	ol.log = r.Log().WithGroup("plugin").With("name", ol.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:   ol,
		Name:     ol.name,
		Priority: 5,
		Transforms: []string{
			string(oam.URL),
		},
		EventType: oam.Service,
		Callback:  ol.check,
	}); err != nil {
		return err
	}

	ol.log.Info("Plugin started")
	return nil
}

func (ol *onionLocation) Stop() {
	ol.log.Info("Plugin stopped")
}

func (ol *onionLocation) check(e *et.Event) error {
	service, ok := e.Entity.Asset.(*platform.Service)
	if !ok {
		return errors.New("failed to extract the Service asset")
	}

	// Only process HTTP/HTTPS services
	if !ol.isHTTPService(service) {
		return nil
	}

	// Extract Onion-Location header from service attributes
	onionLocation := ol.extractOnionLocationHeader(service)
	if onionLocation == "" {
		return nil
	}

	// Validate and normalize the onion location URL
	normalizedURL, err := ol.normalizeOnionURL(onionLocation)
	if err != nil || normalizedURL == "" {
		return nil // Skip invalid URLs
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Service), string(oam.URL), ol.name)
	if err != nil {
		return err
	}

	var findings []*support.Finding
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, ol.source, since) {
		findings = append(findings, ol.lookup(e, e.Entity, normalizedURL, since)...)
	} else {
		go func() {
			if findings := append(findings, ol.query(e, e.Entity, normalizedURL)...); len(findings) > 0 {
				ol.process(e, findings)
			}
		}()
		support.MarkAssetMonitored(e.Session, e.Entity, ol.source)
	}

	if len(findings) > 0 {
		ol.process(e, findings)
	}
	return nil
}

func (ol *onionLocation) lookup(e *et.Event, service *dbt.Entity, urlAddr string, since time.Time) []*support.Finding {
	var findings []*support.Finding

	if edges, err := e.Session.Cache().OutgoingEdges(service, since, "onion_location"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if _, err := e.Session.Cache().GetEdgeTags(edge, since, ol.source.Name); err != nil {
				continue
			}
			if edge.Relation.Key() == "onion_location" {
				if urlEntity, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && urlEntity != nil && urlEntity.Asset.AssetType() == oam.URL {
					if urlAsset := urlEntity.Asset.(*oamurl.URL); urlAsset.Address == urlAddr {
						findings = append(findings, &support.Finding{
							From:     service,
							FromName: service.Asset.Key(),
							To:       urlEntity,
							ToName:   urlAsset.Address,
							Rel:      edge.Relation,
						})
					}
				}
			}
		}
	}
	return findings
}

func (ol *onionLocation) query(e *et.Event, service *dbt.Entity, urlAddr string) []*support.Finding {
	var findings []*support.Finding

	// Create OAM URL asset for the onion location
	urlAsset := &oamurl.URL{
		Address: urlAddr,
	}

	urlEntity, err := e.Session.Cache().CreateAsset(urlAsset)
	if err != nil {
		return findings
	}

	// Create relation between the service and the onion location URL
	relation := &general.SimpleRelation{Name: "onion_location"}

	findings = append(findings, &support.Finding{
		From:     service,
		FromName: service.Asset.Key(),
		To:       urlEntity,
		ToName:   urlAddr,
		Rel:      relation,
	})

	return findings
}

func (ol *onionLocation) process(e *et.Event, findings []*support.Finding) {
	support.ProcessAssetsWithSource(e, findings, ol.source, ol.name, ol.name)
}

// isHTTPService checks if the service is an HTTP or HTTPS service
func (ol *onionLocation) isHTTPService(service *platform.Service) bool {
	if service.Protocol == nil {
		return false
	}

	protocol := strings.ToLower(*service.Protocol)
	return protocol == "http" || protocol == "https"
}

// extractOnionLocationHeader extracts the Onion-Location header value from service attributes
func (ol *onionLocation) extractOnionLocationHeader(service *platform.Service) string {
	if service.Attributes == nil {
		return ""
	}

	// Look for Onion-Location header (case-insensitive)
	for key, values := range service.Attributes {
		if strings.EqualFold(key, "Onion-Location") {
			if len(values) > 0 {
				return strings.TrimSpace(values[0])
			}
		}
	}

	return ""
}

// normalizeOnionURL validates and normalizes the onion location URL
func (ol *onionLocation) normalizeOnionURL(onionLocation string) (string, error) {
	// Parse the URL to validate it
	parsedURL, err := url.Parse(onionLocation)
	if err != nil {
		return "", err
	}

	// Ensure it's a valid onion URL
	if !strings.HasSuffix(parsedURL.Host, ".onion") {
		return "", nil // Not an onion URL, skip
	}

	// Ensure the scheme is set (default to https if missing)
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
	}

	// Only allow http or https schemes
	scheme := strings.ToLower(parsedURL.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", nil // Invalid scheme for onion location
	}

	return parsedURL.String(), nil
}