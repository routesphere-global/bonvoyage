package adminservice

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

type routeCatalogRecord struct {
	entry      RouteCatalogEntry
	searchText string
}

type routeCatalogCache struct {
	ready   bool
	digest  storage.Digest
	records []routeCatalogRecord
}

// ListCurrentRoutes projects a bounded, artifact-bound page from the selected
// immutable snapshot. The full projection is cached by digest because route
// search is a management-plane concern and must not repeatedly decode a large
// Protobuf artifact.
func (service *Service) ListCurrentRoutes(
	ctx context.Context,
	principal Principal,
	query RouteCatalogQuery,
) (RouteCatalogPage, error) {
	if err := requirePermission(principal, permissionRead); err != nil {
		return RouteCatalogPage{}, err
	}
	if err := validateRouteCatalogQuery(query); err != nil {
		return RouteCatalogPage{}, err
	}
	if err := contextError(ctx); err != nil {
		return RouteCatalogPage{}, err
	}

	expected, err := storage.ParseDigest(query.ExpectedArtifactSHA256)
	if err != nil || expected.String() != query.ExpectedArtifactSHA256 {
		return RouteCatalogPage{}, fmt.Errorf("route artifact identity is invalid: %w", ErrInvalidInput)
	}
	selection, err := service.runtime.CurrentRollout()
	if err != nil {
		return RouteCatalogPage{}, err
	}
	record, artifact, decoded, err := service.rolloutArtifact(ctx, selection.Sequence)
	if err != nil {
		return RouteCatalogPage{}, err
	}
	if record.ArtifactDigest != expected {
		return RouteCatalogPage{}, fmt.Errorf("selected route artifact changed: %w", ErrPrecondition)
	}
	records, err := service.catalogRecords(ctx, artifact.Digest, decoded)
	if err != nil {
		return RouteCatalogPage{}, err
	}

	matches, matchingCount, err := pageRouteCatalog(ctx, records, query)
	if err != nil {
		return RouteCatalogPage{}, err
	}

	current, err := service.runtime.CurrentRollout()
	if err != nil {
		return RouteCatalogPage{}, err
	}
	if current.Sequence != selection.Sequence {
		return RouteCatalogPage{}, fmt.Errorf("selected rollout changed during route read: %w", ErrPrecondition)
	}
	return RouteCatalogPage{
		APIVersion: APIVersion, RolloutSequence: record.Sequence,
		SnapshotID: artifact.SnapshotID, ArtifactSHA256: artifact.Digest.String(),
		TotalRoutes: len(records), MatchingRoutes: matchingCount,
		Offset: query.Offset, Limit: query.Limit, Routes: matches,
	}, nil
}

func pageRouteCatalog(
	ctx context.Context,
	records []routeCatalogRecord,
	query RouteCatalogQuery,
) ([]RouteCatalogEntry, int, error) {
	needle := strings.ToLower(strings.TrimSpace(query.Query))
	matches := make([]RouteCatalogEntry, 0, min(len(records), query.Limit))
	matchingCount := 0
	for index, candidate := range records {
		if index%1_024 == 0 {
			if err := contextError(ctx); err != nil {
				return nil, 0, err
			}
		}
		if needle != "" && !strings.Contains(candidate.searchText, needle) {
			continue
		}
		if matchingCount >= query.Offset && len(matches) < query.Limit {
			matches = append(matches, cloneRouteCatalogEntry(candidate.entry))
		}
		matchingCount++
	}
	return matches, matchingCount, nil
}

func validateRouteCatalogQuery(query RouteCatalogQuery) error {
	if query.Offset < 0 || query.Offset > MaxRouteOffset ||
		query.Limit < 1 || query.Limit > MaxRoutePageSize ||
		!utf8.ValidString(query.Query) || len(query.Query) > MaxRouteSearchBytes {
		return ErrInvalidInput
	}
	for _, value := range query.Query {
		if value < 0x20 || value == 0x7f {
			return ErrInvalidInput
		}
	}
	return nil
}

func (service *Service) catalogRecords(
	ctx context.Context,
	digest storage.Digest,
	snapshot *bonvoyagev1.Snapshot,
) ([]routeCatalogRecord, error) {
	service.catalogMu.Lock()
	defer service.catalogMu.Unlock()
	if service.catalog.ready && service.catalog.digest == digest {
		return service.catalog.records, nil
	}
	records := make([]routeCatalogRecord, 0, routeCount(snapshot))
	for _, virtualHost := range snapshot.GetVirtualHosts() {
		for _, route := range virtualHost.GetRoutes() {
			if len(records)%1_024 == 0 {
				if err := contextError(ctx); err != nil {
					return nil, err
				}
			}
			entry := projectRouteCatalogEntry(len(records), virtualHost, route)
			records = append(records, routeCatalogRecord{
				entry: entry, searchText: routeSearchText(entry),
			})
		}
	}
	service.catalog = routeCatalogCache{ready: true, digest: digest, records: records}
	return service.catalog.records, nil
}

func routeCount(snapshot *bonvoyagev1.Snapshot) int {
	count := 0
	for _, virtualHost := range snapshot.GetVirtualHosts() {
		count += len(virtualHost.GetRoutes())
	}
	return count
}

func projectRouteCatalogEntry(
	index int,
	virtualHost *bonvoyagev1.VirtualHost,
	route *bonvoyagev1.Route,
) RouteCatalogEntry {
	matchType, matchValue := routePathMatch(route.GetMatch())
	destinationType, destination := routeDestination(route)
	methods := append([]string(nil), route.GetMatch().GetMethods()...)
	if len(methods) == 0 {
		methods = []string{"ANY"}
	}
	return RouteCatalogEntry{
		Index: index, VirtualHost: virtualHost.GetName(), Route: route.GetName(),
		Domains:   append([]string(nil), virtualHost.GetDomains()...),
		MatchType: matchType, MatchValue: matchValue, Methods: methods,
		DestinationType: destinationType, Destination: destination,
		Policies: routePolicies(route),
	}
}

func routePathMatch(match *bonvoyagev1.RouteMatch) (string, string) {
	if match == nil {
		return "ANY", "/"
	}
	switch value := match.GetPathMatch().(type) {
	case *bonvoyagev1.RouteMatch_PathExact:
		return "EXACT", value.PathExact
	case *bonvoyagev1.RouteMatch_PathPrefix:
		return "PREFIX", value.PathPrefix
	case *bonvoyagev1.RouteMatch_SafeRegex:
		return "SAFE_REGEX", value.SafeRegex
	default:
		return "ANY", "/"
	}
}

func routeDestination(route *bonvoyagev1.Route) (string, string) {
	if weighted := route.GetWeightedClusters(); len(weighted) != 0 {
		parts := make([]string, 0, len(weighted))
		for _, cluster := range weighted {
			parts = append(parts, cluster.GetClusterName()+":"+strconv.FormatUint(uint64(cluster.GetWeight()), 10))
		}
		return "WEIGHTED_CLUSTERS", strings.Join(parts, ", ")
	}
	if route.GetClusterName() != "" {
		return "CLUSTER", route.GetClusterName()
	}
	if fixed := route.GetFixedResponse(); fixed != nil {
		return "FIXED_RESPONSE", "HTTP " + strconv.FormatUint(uint64(fixed.GetStatusCode()), 10)
	}
	if redirect := route.GetRedirect(); redirect != nil {
		return "REDIRECT", "HTTP " + strconv.FormatUint(uint64(redirect.GetStatusCode()), 10)
	}
	return "UNRESOLVED", "Unavailable"
}

func routePolicies(route *bonvoyagev1.Route) []string {
	policies := make([]string, 0, 10)
	if route.GetMaxConcurrentRequestsPerShard() != 0 {
		policies = append(policies, "ADMISSION")
	}
	if route.GetLocalRateLimit() != nil {
		policies = append(policies, "RATE_LIMIT")
	}
	if route.GetApiKeyAuth() != nil {
		policies = append(policies, "API_KEY")
	}
	if route.GetJwtAuth() != nil {
		policies = append(policies, "JWT")
	}
	if route.GetSourceIpPolicy() != nil {
		policies = append(policies, "SOURCE_IP")
	}
	if route.GetCors() != nil {
		policies = append(policies, "CORS")
	}
	if route.GetRequestContent() != nil {
		policies = append(policies, "REQUEST_CONTENT")
	}
	if route.GetHeaderTransformations() != nil {
		policies = append(policies, "HEADER_TRANSFORM")
	}
	if route.GetRewrite() != nil {
		policies = append(policies, "REWRITE")
	}
	if route.GetWebsocket() != nil {
		policies = append(policies, "WEBSOCKET")
	}
	return policies
}

func routeSearchText(entry RouteCatalogEntry) string {
	values := []string{
		entry.VirtualHost, entry.Route, strings.Join(entry.Domains, " "),
		entry.MatchType, entry.MatchValue, strings.Join(entry.Methods, " "),
		entry.DestinationType, entry.Destination, strings.Join(entry.Policies, " "),
	}
	return strings.ToLower(strings.Join(values, "\x00"))
}

func cloneRouteCatalogEntry(entry RouteCatalogEntry) RouteCatalogEntry {
	entry.Domains = slices.Clone(entry.Domains)
	entry.Methods = slices.Clone(entry.Methods)
	entry.Policies = slices.Clone(entry.Policies)
	return entry
}
