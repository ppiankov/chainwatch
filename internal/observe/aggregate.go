package observe

import (
	"sort"
	"strings"
)

// ClusterObservation holds the findings reported for one host in a cluster.
type ClusterObservation struct {
	ClusterName string
	Host        string
	Findings    []Finding
}

// Finding is a normalized observation ready for aggregation.
type Finding struct {
	Type     string
	Severity string
	Detail   string
	Hash     string
}

// AggregateResult is the rolled-up view across all observed clusters.
type AggregateResult struct {
	Clusters      []ClusterSummary
	CrossCluster  []ConsolidatedFinding
	TotalFindings int
	BySeverity    map[string]int
	ByType        map[string]int
}

// ClusterSummary captures cluster-level health counts.
type ClusterSummary struct {
	Name         string
	HostCount    int
	FindingCount int
	BySeverity   map[string]int
}

// ConsolidatedFinding highlights a finding type shared across clusters.
type ConsolidatedFinding struct {
	Type           string
	Severity       string
	Clusters       []string
	Count          int
	Representative Finding
}

var severityRanks = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

type clusterAccumulator struct {
	hosts        map[string]struct{}
	findingCount int
	bySeverity   map[string]int
	seenHashes   map[string]struct{}
}

type consolidatedAccumulator struct {
	count          int
	clusters       map[string]struct{}
	representative Finding
}

// Aggregate rolls host-level observations into cluster and cross-cluster views.
func Aggregate(observations []ClusterObservation) *AggregateResult {
	result := &AggregateResult{
		Clusters:     []ClusterSummary{},
		CrossCluster: []ConsolidatedFinding{},
		BySeverity:   map[string]int{},
		ByType:       map[string]int{},
	}
	if len(observations) == 0 {
		return result
	}

	clusterStates := map[string]*clusterAccumulator{}
	crossClusterStates := map[string]*consolidatedAccumulator{}

	for _, observation := range observations {
		clusterName := strings.TrimSpace(observation.ClusterName)
		clusterState := clusterStates[clusterName]
		if clusterState == nil {
			clusterState = &clusterAccumulator{
				hosts:      map[string]struct{}{},
				bySeverity: map[string]int{},
				seenHashes: map[string]struct{}{},
			}
			clusterStates[clusterName] = clusterState
		}

		host := strings.TrimSpace(observation.Host)
		if host != "" {
			clusterState.hosts[host] = struct{}{}
		}

		for _, rawFinding := range observation.Findings {
			finding := normalizeFinding(rawFinding)
			if finding.Hash != "" {
				if _, seen := clusterState.seenHashes[finding.Hash]; seen {
					continue
				}
				clusterState.seenHashes[finding.Hash] = struct{}{}
			}

			clusterState.findingCount++
			result.TotalFindings++

			if finding.Severity != "" {
				clusterState.bySeverity[finding.Severity]++
				result.BySeverity[finding.Severity]++
			}
			if finding.Type != "" {
				result.ByType[finding.Type]++

				crossClusterState := crossClusterStates[finding.Type]
				if crossClusterState == nil {
					crossClusterState = &consolidatedAccumulator{
						clusters:       map[string]struct{}{},
						representative: finding,
					}
					crossClusterStates[finding.Type] = crossClusterState
				}
				crossClusterState.count++
				crossClusterState.clusters[clusterName] = struct{}{}
				if shouldReplaceRepresentative(finding, crossClusterState.representative) {
					crossClusterState.representative = finding
				}
			}
		}
	}

	clusterNames := make([]string, 0, len(clusterStates))
	for name := range clusterStates {
		clusterNames = append(clusterNames, name)
	}
	sort.Strings(clusterNames)

	for _, name := range clusterNames {
		clusterState := clusterStates[name]
		result.Clusters = append(result.Clusters, ClusterSummary{
			Name:         name,
			HostCount:    len(clusterState.hosts),
			FindingCount: clusterState.findingCount,
			BySeverity:   cloneCounts(clusterState.bySeverity),
		})
	}

	crossTypes := make([]string, 0, len(crossClusterStates))
	for findingType, state := range crossClusterStates {
		if len(state.clusters) < 2 {
			continue
		}
		crossTypes = append(crossTypes, findingType)
	}
	sort.Strings(crossTypes)

	for _, findingType := range crossTypes {
		state := crossClusterStates[findingType]
		clusters := make([]string, 0, len(state.clusters))
		for clusterName := range state.clusters {
			clusters = append(clusters, clusterName)
		}
		sort.Strings(clusters)

		result.CrossCluster = append(result.CrossCluster, ConsolidatedFinding{
			Type:           findingType,
			Severity:       state.representative.Severity,
			Clusters:       clusters,
			Count:          state.count,
			Representative: state.representative,
		})
	}

	return result
}

func normalizeFinding(f Finding) Finding {
	return Finding{
		Type:     normalizeKey(f.Type),
		Severity: normalizeKey(f.Severity),
		Detail:   strings.TrimSpace(f.Detail),
		Hash:     strings.TrimSpace(f.Hash),
	}
}

func normalizeKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func cloneCounts(counts map[string]int) map[string]int {
	cloned := make(map[string]int, len(counts))
	for key, value := range counts {
		cloned[key] = value
	}
	return cloned
}

func shouldReplaceRepresentative(candidate, current Finding) bool {
	candidateRank := severityRank(candidate.Severity)
	currentRank := severityRank(current.Severity)
	if candidateRank != currentRank {
		return candidateRank > currentRank
	}

	if candidate.Detail != current.Detail {
		return candidate.Detail < current.Detail
	}
	if candidate.Hash != current.Hash {
		return candidate.Hash < current.Hash
	}
	if candidate.Severity != current.Severity {
		return candidate.Severity < current.Severity
	}

	return false
}

func severityRank(severity string) int {
	return severityRanks[severity]
}
