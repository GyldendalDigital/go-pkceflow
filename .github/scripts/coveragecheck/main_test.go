package main

import (
	"math"
	"strings"
	"testing"
)

func TestParsePackageList(t *testing.T) {
	packages, err := parsePackageList(strings.NewReader(
		`{"ImportPath":"example.com/project/pkg"}` + "\n" +
			`{"ImportPath":"example.com/project"}`,
	))
	if err != nil {
		t.Fatalf("parsePackageList: %v", err)
	}
	want := []string{"example.com/project", "example.com/project/pkg"}
	if len(packages) != len(want) {
		t.Fatalf("packages = %v, want %v", packages, want)
	}
	for index := range want {
		if packages[index] != want[index] {
			t.Fatalf("packages = %v, want %v", packages, want)
		}
	}
}

func TestParsePackageListRejectsInvalidDiscovery(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "missing import path", input: `{}`},
		{name: "duplicate", input: `{"ImportPath":"example.com/project"}{"ImportPath":"example.com/project"}`},
		{name: "malformed", input: `{`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parsePackageList(strings.NewReader(tt.input)); err == nil {
				t.Fatal("parsePackageList accepted invalid discovery data")
			}
		})
	}
}

func TestParseProfileCountsStatementsByPackage(t *testing.T) {
	profile := `mode: atomic
example.com/project/root.go:1.1,2.1 2 1
example.com/project/root.go:3.1,4.1 3 0
example.com/project/pkg/pkg.go:1.1,1.2 0 1
example.com/project/pkg/pkg.go:2.1,3.1 4 2
`
	coverage, err := parseProfile(strings.NewReader(profile))
	if err != nil {
		t.Fatalf("parseProfile: %v", err)
	}
	if got := coverage["example.com/project"]; got != (packageCoverage{covered: 2, total: 5}) {
		t.Fatalf("root coverage = %+v", got)
	}
	if got := coverage["example.com/project/pkg"]; got != (packageCoverage{covered: 4, total: 4}) {
		t.Fatalf("pkg coverage = %+v", got)
	}
}

func TestParseProfileRejectsMalformedData(t *testing.T) {
	tests := []struct {
		name    string
		profile string
	}{
		{name: "missing mode", profile: ""},
		{name: "invalid mode line", profile: "mode count\n"},
		{name: "unsupported mode", profile: "mode: other\n"},
		{name: "missing fields", profile: "mode: set\nexample.com/project/a.go:1.1,2.1 1\n"},
		{name: "invalid location", profile: "mode: set\nexample.com/project/a.go 1 1\n"},
		{name: "non-go file", profile: "mode: set\nexample.com/project/a.txt:1.1,2.1 1 1\n"},
		{name: "invalid start", profile: "mode: set\nexample.com/project/a.go:0.1,2.1 1 1\n"},
		{name: "backwards range", profile: "mode: set\nexample.com/project/a.go:2.1,1.1 1 1\n"},
		{name: "invalid statements", profile: "mode: set\nexample.com/project/a.go:1.1,2.1 -1 1\n"},
		{name: "invalid count", profile: "mode: set\nexample.com/project/a.go:1.1,2.1 1 nope\n"},
		{name: "duplicate block", profile: "mode: set\nexample.com/project/a.go:1.1,2.1 1 1\nexample.com/project/a.go:1.1,2.1 1 1\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseProfile(strings.NewReader(tt.profile)); err == nil {
				t.Fatal("parseProfile accepted malformed data")
			}
		})
	}
}

func TestEvaluateCoverageAppliesExactPackageAndAggregateFloors(t *testing.T) {
	policy := testPolicy()
	packages := []string{
		"example.com/project",
		"example.com/project/examples/cli",
		"example.com/project/future",
		"example.com/project/pkg",
		"example.com/project/zero",
	}
	coverage := map[string]packageCoverage{
		"example.com/project":              {covered: 90, total: 100},
		"example.com/project/examples/cli": {covered: 0, total: 1000},
		"example.com/project/future":       {covered: 70, total: 100},
		"example.com/project/pkg":          {covered: 80, total: 100},
		"example.com/project/zero":         {},
	}

	evaluated := evaluateCoverage(packages, coverage, policy)
	if evaluated.failed() {
		t.Fatalf("exact-floor evaluation failed: %+v", evaluated)
	}
	if got := evaluated.results[len(evaluated.results)-1]; got.covered != 240 || got.total != 300 || got.status != "PASS" {
		t.Fatalf("aggregate result = %+v, want exact 80%% pass", got)
	}
	for _, result := range evaluated.results {
		if strings.Contains(result.name, "examples") {
			t.Fatalf("example package was evaluated: %+v", result)
		}
		if result.name == "zero" && result.status != "N/A" {
			t.Fatalf("zero-statement result = %+v, want N/A", result)
		}
	}
}

func TestEvaluateCoverageRejectsJustBelowAndUsesWeightedAggregate(t *testing.T) {
	policy := testPolicy()
	policy.aggregateMinimum = 85
	packages := []string{"example.com/project", "example.com/project/pkg"}
	coverage := map[string]packageCoverage{
		"example.com/project":     {covered: 8, total: 10},
		"example.com/project/pkg": {covered: 1, total: 1},
	}

	evaluated := evaluateCoverage(packages, coverage, policy)
	if !evaluated.failed() {
		t.Fatal("weighted aggregate below 85% passed")
	}
	aggregate := evaluated.results[len(evaluated.results)-1]
	if aggregate.covered != 9 || aggregate.total != 11 || aggregate.status != "FAIL" {
		t.Fatalf("aggregate result = %+v, want 9/11 failure", aggregate)
	}

	policy.aggregateMinimum = 0
	coverage["example.com/project"] = packageCoverage{covered: 89, total: 100}
	evaluated = evaluateCoverage(packages, coverage, policy)
	if evaluated.results[0].status != "FAIL" {
		t.Fatalf("just-below package result = %+v, want failure", evaluated.results[0])
	}
}

func TestEvaluateCoverageReconcilesDiscoveryProfileAndPolicy(t *testing.T) {
	tests := []struct {
		name     string
		packages []string
		coverage map[string]packageCoverage
		mutate   func(*coveragePolicy)
	}{
		{
			name:     "missing profile package",
			packages: []string{"example.com/project", "example.com/project/pkg"},
			coverage: map[string]packageCoverage{"example.com/project": {covered: 90, total: 100}},
		},
		{
			name:     "unexpected profile package",
			packages: []string{"example.com/project", "example.com/project/pkg"},
			coverage: map[string]packageCoverage{
				"example.com/project":         {covered: 90, total: 100},
				"example.com/project/pkg":     {covered: 80, total: 100},
				"example.com/project/unknown": {covered: 1, total: 1},
			},
		},
		{
			name:     "stale policy package",
			packages: []string{"example.com/project", "example.com/project/pkg"},
			coverage: map[string]packageCoverage{
				"example.com/project":     {covered: 90, total: 100},
				"example.com/project/pkg": {covered: 80, total: 100},
			},
			mutate: func(policy *coveragePolicy) {
				policy.packageMinimums["example.com/project/removed"] = 70
			},
		},
		{
			name:     "outside module discovery",
			packages: []string{"example.com/project", "example.net/other", "example.com/project/pkg"},
			coverage: map[string]packageCoverage{
				"example.com/project":     {covered: 90, total: 100},
				"example.com/project/pkg": {covered: 80, total: 100},
				"example.net/other":       {covered: 1, total: 1},
			},
		},
		{
			name:     "invalid coverage counts",
			packages: []string{"example.com/project", "example.com/project/pkg"},
			coverage: map[string]packageCoverage{
				"example.com/project":     {covered: 101, total: 100},
				"example.com/project/pkg": {covered: 80, total: 100},
			},
		},
		{
			name:     "invalid policy minimum",
			packages: []string{"example.com/project", "example.com/project/pkg"},
			coverage: map[string]packageCoverage{
				"example.com/project":     {covered: 90, total: 100},
				"example.com/project/pkg": {covered: 80, total: 100},
			},
			mutate: func(policy *coveragePolicy) {
				policy.defaultMinimum = 101
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := testPolicy()
			if tt.mutate != nil {
				tt.mutate(&policy)
			}
			if evaluated := evaluateCoverage(tt.packages, tt.coverage, policy); !evaluated.failed() {
				t.Fatalf("reconciliation error passed: %+v", evaluated)
			}
		})
	}
}

func TestMeetsMinimumUsesExactOverflowSafeArithmetic(t *testing.T) {
	coverage := packageCoverage{
		covered: (math.MaxInt64 - 1) / 2,
		total:   math.MaxInt64 - 1,
	}
	if !meetsMinimum(coverage, 50) {
		t.Fatal("exact 50% coverage failed")
	}
	if meetsMinimum(coverage, 51) {
		t.Fatal("coverage below 51% passed")
	}
}

func TestExcludedPackageMatchesOnlyExamplesSubtree(t *testing.T) {
	if !excludedPackage("example.com/project/examples", "example.com/project") ||
		!excludedPackage("example.com/project/examples/cli", "example.com/project") {
		t.Fatal("examples subtree was not excluded")
	}
	if excludedPackage("example.com/project/examples-extra", "example.com/project") ||
		excludedPackage("example.com/project/pkg/examples", "example.com/project") {
		t.Fatal("non-examples package was excluded")
	}
}

func testPolicy() coveragePolicy {
	return coveragePolicy{
		modulePath:       "example.com/project",
		defaultMinimum:   70,
		aggregateMinimum: 80,
		packageMinimums: map[string]int64{
			"example.com/project":     90,
			"example.com/project/pkg": 80,
		},
	}
}
