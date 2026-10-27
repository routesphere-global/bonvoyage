package adminservice

import (
	"context"
	"fmt"
	"testing"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/storage"
)

func TestRouteCatalogKeepsOneHundredThousandRoutesServerBounded(t *testing.T) {
	const routeCount = 100_000
	routes := make([]*bonvoyagev1.Route, 0, routeCount)
	for index := 0; index < routeCount; index++ {
		routes = append(routes, &bonvoyagev1.Route{
			Name: fmt.Sprintf("route-%06d", index),
			Match: &bonvoyagev1.RouteMatch{PathMatch: &bonvoyagev1.RouteMatch_PathExact{
				PathExact: fmt.Sprintf("/api/resources/%06d", index),
			}},
			ClusterName: fmt.Sprintf("cluster-%d", index%10),
		})
	}
	snapshot := &bonvoyagev1.Snapshot{VirtualHosts: []*bonvoyagev1.VirtualHost{{
		Name: "large-catalog", Domains: []string{"api.example.test"}, Routes: routes,
	}}}
	service := &Service{}
	records, err := service.catalogRecords(context.Background(), storage.Sum([]byte("large-catalog")), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != routeCount {
		t.Fatalf("records = %d, want %d", len(records), routeCount)
	}

	page, matching, err := pageRouteCatalog(context.Background(), records, RouteCatalogQuery{
		Offset: 99_950, Limit: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	if matching != routeCount || len(page) != 50 || page[0].Index != 99_950 || page[49].Index != 99_999 {
		t.Fatalf("bounded final page: matching=%d first=%d last=%d size=%d", matching, page[0].Index, page[49].Index, len(page))
	}

	filtered, matching, err := pageRouteCatalog(context.Background(), records, RouteCatalogQuery{
		Offset: 9_990, Limit: 10, Query: "CLUSTER-7",
	})
	if err != nil {
		t.Fatal(err)
	}
	if matching != 10_000 || len(filtered) != 10 || filtered[0].Destination != "cluster-7" ||
		filtered[9].Index != 99_997 {
		t.Fatalf("bounded filtered page: matching=%d first=%#v last=%#v size=%d", matching, filtered[0], filtered[9], len(filtered))
	}
}
