package observe

import (
	"reflect"
	"testing"
)

func TestAggregateSingleClusterNoCrossClusterPatterns(t *testing.T) {
	t.Parallel()

	result := Aggregate([]ClusterObservation{
		{
			ClusterName: "alpha",
			Host:        "alpha-1",
			Findings: []Finding{
				{Type: "process_anomaly", Severity: "high", Detail: "unexpected shell", Hash: "alpha-p1"},
				{Type: "config_modified", Severity: "medium", Detail: "nginx.conf changed", Hash: "alpha-c1"},
			},
		},
	})

	if result == nil {
		t.Fatal("Aggregate returned nil")
	}
	if result.TotalFindings != 2 {
		t.Fatalf("TotalFindings = %d, want 2", result.TotalFindings)
	}
	if len(result.CrossCluster) != 0 {
		t.Fatalf("CrossCluster len = %d, want 0", len(result.CrossCluster))
	}
	if !reflect.DeepEqual(result.ByType, map[string]int{
		"config_modified": 1,
		"process_anomaly": 1,
	}) {
		t.Fatalf("ByType = %#v", result.ByType)
	}
	if !reflect.DeepEqual(result.BySeverity, map[string]int{
		"high":   1,
		"medium": 1,
	}) {
		t.Fatalf("BySeverity = %#v", result.BySeverity)
	}
	if len(result.Clusters) != 1 {
		t.Fatalf("Clusters len = %d, want 1", len(result.Clusters))
	}

	cluster := result.Clusters[0]
	if cluster.Name != "alpha" {
		t.Fatalf("cluster name = %q, want alpha", cluster.Name)
	}
	if cluster.HostCount != 1 {
		t.Fatalf("cluster HostCount = %d, want 1", cluster.HostCount)
	}
	if cluster.FindingCount != 2 {
		t.Fatalf("cluster FindingCount = %d, want 2", cluster.FindingCount)
	}
	if !reflect.DeepEqual(cluster.BySeverity, map[string]int{
		"high":   1,
		"medium": 1,
	}) {
		t.Fatalf("cluster BySeverity = %#v", cluster.BySeverity)
	}
}

func TestAggregateThreeClustersConsolidatesSharedType(t *testing.T) {
	t.Parallel()

	result := Aggregate([]ClusterObservation{
		{
			ClusterName: "alpha",
			Host:        "alpha-1",
			Findings: []Finding{
				{Type: "network_anomaly", Severity: "medium", Detail: "port 4444 listening", Hash: "alpha-n1"},
			},
		},
		{
			ClusterName: "beta",
			Host:        "beta-1",
			Findings: []Finding{
				{Type: "network_anomaly", Severity: "high", Detail: "reverse shell listener", Hash: "beta-n1"},
			},
		},
		{
			ClusterName: "gamma",
			Host:        "gamma-1",
			Findings: []Finding{
				{Type: "config_modified", Severity: "low", Detail: "banner changed", Hash: "gamma-c1"},
			},
		},
	})

	if len(result.CrossCluster) != 1 {
		t.Fatalf("CrossCluster len = %d, want 1", len(result.CrossCluster))
	}

	consolidated := result.CrossCluster[0]
	if consolidated.Type != "network_anomaly" {
		t.Fatalf("Type = %q, want network_anomaly", consolidated.Type)
	}
	if consolidated.Severity != "high" {
		t.Fatalf("Severity = %q, want high", consolidated.Severity)
	}
	if consolidated.Count != 2 {
		t.Fatalf("Count = %d, want 2", consolidated.Count)
	}
	if !reflect.DeepEqual(consolidated.Clusters, []string{"alpha", "beta"}) {
		t.Fatalf("Clusters = %#v", consolidated.Clusters)
	}
	if consolidated.Representative.Hash != "beta-n1" {
		t.Fatalf("Representative.Hash = %q, want beta-n1", consolidated.Representative.Hash)
	}
}

func TestAggregateSeverityCountsRollUpCorrectly(t *testing.T) {
	t.Parallel()

	result := Aggregate([]ClusterObservation{
		{
			ClusterName: "alpha",
			Host:        "alpha-1",
			Findings: []Finding{
				{Type: "process_anomaly", Severity: "high", Detail: "unexpected shell", Hash: "alpha-p1"},
				{Type: "config_modified", Severity: "low", Detail: "motd changed", Hash: "alpha-c1"},
			},
		},
		{
			ClusterName: "beta",
			Host:        "beta-1",
			Findings: []Finding{
				{Type: "network_anomaly", Severity: "critical", Detail: "egress tunnel", Hash: "beta-n1"},
				{Type: "unauthorized_user", Severity: "high", Detail: "uid 0 backdoor", Hash: "beta-u1"},
			},
		},
	})

	if !reflect.DeepEqual(result.BySeverity, map[string]int{
		"critical": 1,
		"high":     2,
		"low":      1,
	}) {
		t.Fatalf("BySeverity = %#v", result.BySeverity)
	}
	if result.TotalFindings != 4 {
		t.Fatalf("TotalFindings = %d, want 4", result.TotalFindings)
	}
}

func TestAggregateEmptyObservationsReturnsEmptyResult(t *testing.T) {
	t.Parallel()

	result := Aggregate(nil)
	if result == nil {
		t.Fatal("Aggregate returned nil")
	}
	if result.TotalFindings != 0 {
		t.Fatalf("TotalFindings = %d, want 0", result.TotalFindings)
	}
	if len(result.Clusters) != 0 {
		t.Fatalf("Clusters len = %d, want 0", len(result.Clusters))
	}
	if len(result.CrossCluster) != 0 {
		t.Fatalf("CrossCluster len = %d, want 0", len(result.CrossCluster))
	}
	if result.BySeverity == nil {
		t.Fatal("BySeverity is nil")
	}
	if result.ByType == nil {
		t.Fatal("ByType is nil")
	}
	if len(result.BySeverity) != 0 {
		t.Fatalf("BySeverity len = %d, want 0", len(result.BySeverity))
	}
	if len(result.ByType) != 0 {
		t.Fatalf("ByType len = %d, want 0", len(result.ByType))
	}
}

func TestAggregateDedupsSameFindingHashPerCluster(t *testing.T) {
	t.Parallel()

	result := Aggregate([]ClusterObservation{
		{
			ClusterName: "alpha",
			Host:        "alpha-1",
			Findings: []Finding{
				{Type: "process_anomaly", Severity: "high", Detail: "unexpected shell", Hash: "shared-process"},
			},
		},
		{
			ClusterName: "alpha",
			Host:        "alpha-2",
			Findings: []Finding{
				{Type: "process_anomaly", Severity: "high", Detail: "unexpected shell", Hash: "shared-process"},
			},
		},
		{
			ClusterName: "beta",
			Host:        "beta-1",
			Findings: []Finding{
				{Type: "process_anomaly", Severity: "high", Detail: "unexpected shell", Hash: "shared-process"},
			},
		},
	})

	if result.TotalFindings != 2 {
		t.Fatalf("TotalFindings = %d, want 2", result.TotalFindings)
	}
	if !reflect.DeepEqual(result.BySeverity, map[string]int{"high": 2}) {
		t.Fatalf("BySeverity = %#v", result.BySeverity)
	}
	if !reflect.DeepEqual(result.ByType, map[string]int{"process_anomaly": 2}) {
		t.Fatalf("ByType = %#v", result.ByType)
	}
	if len(result.Clusters) != 2 {
		t.Fatalf("Clusters len = %d, want 2", len(result.Clusters))
	}
	if result.Clusters[0].Name != "alpha" {
		t.Fatalf("first cluster = %q, want alpha", result.Clusters[0].Name)
	}
	if result.Clusters[0].HostCount != 2 {
		t.Fatalf("alpha HostCount = %d, want 2", result.Clusters[0].HostCount)
	}
	if result.Clusters[0].FindingCount != 1 {
		t.Fatalf("alpha FindingCount = %d, want 1", result.Clusters[0].FindingCount)
	}
	if len(result.CrossCluster) != 1 {
		t.Fatalf("CrossCluster len = %d, want 1", len(result.CrossCluster))
	}
	if !reflect.DeepEqual(result.CrossCluster[0].Clusters, []string{"alpha", "beta"}) {
		t.Fatalf("CrossCluster[0].Clusters = %#v", result.CrossCluster[0].Clusters)
	}
}
