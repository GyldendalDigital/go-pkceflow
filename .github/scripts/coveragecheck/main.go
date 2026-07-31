package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/bits"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const modulePath = "github.com/GyldendalDigital/go-pkceflow"

type coveragePolicy struct {
	modulePath       string
	defaultMinimum   int64
	aggregateMinimum int64
	packageMinimums  map[string]int64
}

var repositoryPolicy = coveragePolicy{
	modulePath:       modulePath,
	defaultMinimum:   70,
	aggregateMinimum: 80,
	packageMinimums: map[string]int64{
		modulePath:                  88,
		modulePath + "/desktopflow": 80,
		modulePath + "/eventbus":    80,
		modulePath + "/filestore":   80,
		modulePath + "/mobileflow":  80,
		modulePath + "/oidctest":    70,
	},
}

type packageCoverage struct {
	covered int64
	total   int64
}

type coverageResult struct {
	name    string
	covered int64
	total   int64
	minimum int64
	status  string
}

type evaluation struct {
	results  []coverageResult
	problems []string
}

func main() {
	root := flag.String("root", ".", "module root used for package discovery")
	profile := flag.String("profile", "coverage.out", "Go coverprofile to evaluate")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "coveragecheck: positional arguments are not supported")
		os.Exit(2)
	}

	if err := run(*root, *profile, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "coveragecheck: %v\n", err)
		os.Exit(1)
	}
}

func run(root, profile string, output io.Writer) error {
	packages, err := discoverPackages(root)
	if err != nil {
		return err
	}

	profilePath := profile
	if !filepath.IsAbs(profilePath) {
		profilePath = filepath.Join(root, profilePath)
	}
	file, err := os.Open(profilePath) //nolint:gosec // path is an explicit local CLI argument
	if err != nil {
		return fmt.Errorf("open coverage profile %q: %w", profilePath, err)
	}
	coverage, parseErr := parseProfile(file)
	closeErr := file.Close()
	if parseErr != nil {
		return parseErr
	}
	if closeErr != nil {
		return fmt.Errorf("close coverage profile %q: %w", profilePath, closeErr)
	}

	evaluated := evaluateCoverage(packages, coverage, repositoryPolicy)
	writeEvaluation(output, evaluated, repositoryPolicy)
	if evaluated.failed() {
		return errors.New("coverage policy failed")
	}
	return nil
}

func discoverPackages(root string) ([]string, error) {
	command := exec.Command("go", "list", "-json", "./...") //nolint:gosec // fixed tool and arguments
	command.Dir = root
	data, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("discover packages with go list: %w: %s", err, bytes.TrimSpace(data))
	}
	packages, err := parsePackageList(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decode go list output: %w", err)
	}
	return packages, nil
}

func parsePackageList(input io.Reader) ([]string, error) {
	decoder := json.NewDecoder(input)
	seen := make(map[string]struct{})
	var packages []string
	for {
		var listed struct {
			ImportPath string
		}
		err := decoder.Decode(&listed)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if listed.ImportPath == "" {
			return nil, errors.New("go list returned a package without an import path")
		}
		if _, exists := seen[listed.ImportPath]; exists {
			return nil, fmt.Errorf("go list returned duplicate package %q", listed.ImportPath)
		}
		seen[listed.ImportPath] = struct{}{}
		packages = append(packages, listed.ImportPath)
	}
	if len(packages) == 0 {
		return nil, errors.New("go list returned no packages")
	}
	sort.Strings(packages)
	return packages, nil
}

func parseProfile(input io.Reader) (map[string]packageCoverage, error) {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	coverage := make(map[string]packageCoverage)
	blocks := make(map[string]struct{})
	lineNumber := 0
	modeSeen := false

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if !modeSeen {
			if err := parseMode(line); err != nil {
				return nil, fmt.Errorf("coverage profile line %d: %w", lineNumber, err)
			}
			modeSeen = true
			continue
		}

		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("coverage profile line %d: want block, statements, and count", lineNumber)
		}
		filePath, err := parseBlockLocation(fields[0])
		if err != nil {
			return nil, fmt.Errorf("coverage profile line %d: %w", lineNumber, err)
		}
		if _, exists := blocks[fields[0]]; exists {
			return nil, fmt.Errorf("coverage profile line %d: duplicate block %q", lineNumber, fields[0])
		}
		blocks[fields[0]] = struct{}{}

		statements, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || statements < 0 {
			return nil, fmt.Errorf("coverage profile line %d: invalid statement count %q", lineNumber, fields[1])
		}
		count, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("coverage profile line %d: invalid execution count %q", lineNumber, fields[2])
		}

		packagePath := path.Dir(filePath)
		current := coverage[packagePath]
		if statements > math.MaxInt64-current.total {
			return nil, fmt.Errorf("coverage profile line %d: statement total overflow", lineNumber)
		}
		current.total += statements
		if count > 0 {
			if statements > math.MaxInt64-current.covered {
				return nil, fmt.Errorf("coverage profile line %d: covered total overflow", lineNumber)
			}
			current.covered += statements
		}
		coverage[packagePath] = current
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read coverage profile: %w", err)
	}
	if !modeSeen {
		return nil, errors.New("coverage profile is missing a mode line")
	}
	return coverage, nil
}

func parseMode(line string) error {
	mode, ok := strings.CutPrefix(line, "mode: ")
	if !ok {
		return fmt.Errorf("expected mode line, got %q", line)
	}
	switch mode {
	case "set", "count", "atomic":
		return nil
	default:
		return fmt.Errorf("unsupported coverage mode %q", mode)
	}
}

func parseBlockLocation(location string) (string, error) {
	separator := strings.LastIndex(location, ":")
	if separator <= 0 || separator == len(location)-1 {
		return "", fmt.Errorf("invalid block location %q", location)
	}
	filePath := location[:separator]
	if !strings.HasSuffix(filePath, ".go") {
		return "", fmt.Errorf("coverage block file is not Go source: %q", filePath)
	}
	points := strings.Split(location[separator+1:], ",")
	if len(points) != 2 {
		return "", fmt.Errorf("invalid block range %q", location)
	}
	startLine, startColumn, err := parsePosition(points[0])
	if err != nil {
		return "", fmt.Errorf("invalid block start in %q: %w", location, err)
	}
	endLine, endColumn, err := parsePosition(points[1])
	if err != nil {
		return "", fmt.Errorf("invalid block end in %q: %w", location, err)
	}
	if endLine < startLine || (endLine == startLine && endColumn < startColumn) {
		return "", fmt.Errorf("block range ends before it starts: %q", location)
	}
	return filePath, nil
}

func parsePosition(position string) (int64, int64, error) {
	line, column, ok := strings.Cut(position, ".")
	if !ok {
		return 0, 0, errors.New("position must contain line and column")
	}
	lineNumber, err := strconv.ParseInt(line, 10, 64)
	if err != nil || lineNumber <= 0 {
		return 0, 0, fmt.Errorf("invalid line %q", line)
	}
	columnNumber, err := strconv.ParseInt(column, 10, 64)
	if err != nil || columnNumber <= 0 {
		return 0, 0, fmt.Errorf("invalid column %q", column)
	}
	return lineNumber, columnNumber, nil
}

func evaluateCoverage(
	packages []string,
	coverage map[string]packageCoverage,
	policy coveragePolicy,
) evaluation {
	result := evaluation{}
	validatePolicy(policy, &result)
	discovered := make(map[string]struct{}, len(packages))
	for _, packagePath := range packages {
		if _, exists := discovered[packagePath]; exists {
			result.problems = append(result.problems, fmt.Sprintf("duplicate discovered package %q", packagePath))
			continue
		}
		discovered[packagePath] = struct{}{}
		if !withinModule(packagePath, policy.modulePath) {
			result.problems = append(result.problems, fmt.Sprintf("discovered package %q is outside module %q", packagePath, policy.modulePath))
		}
	}

	for packagePath := range policy.packageMinimums {
		if _, exists := discovered[packagePath]; !exists {
			result.problems = append(result.problems, fmt.Sprintf("configured package %q was not discovered", packagePath))
		}
	}
	for packagePath := range coverage {
		if _, exists := discovered[packagePath]; !exists {
			result.problems = append(result.problems, fmt.Sprintf("profile package %q was not discovered", packagePath))
		}
	}

	sortedPackages := make([]string, 0, len(discovered))
	for packagePath := range discovered {
		sortedPackages = append(sortedPackages, packagePath)
	}
	sort.Strings(sortedPackages)
	var aggregate packageCoverage
	for _, packagePath := range sortedPackages {
		if excludedPackage(packagePath, policy.modulePath) {
			continue
		}
		packageCoverage, exists := coverage[packagePath]
		if !exists {
			result.problems = append(result.problems, fmt.Sprintf("discovered package %q is missing from the coverage profile", packagePath))
			continue
		}
		if packageCoverage.covered < 0 || packageCoverage.total < 0 || packageCoverage.covered > packageCoverage.total {
			result.problems = append(result.problems, fmt.Sprintf("package %q has invalid coverage counts %d/%d", packagePath, packageCoverage.covered, packageCoverage.total))
			continue
		}
		minimum := policy.defaultMinimum
		if configured, ok := policy.packageMinimums[packagePath]; ok {
			minimum = configured
		}
		status := "PASS"
		if packageCoverage.total == 0 {
			status = "N/A"
		} else if !meetsMinimum(packageCoverage, minimum) {
			status = "FAIL"
		}
		result.results = append(result.results, coverageResult{
			name:    displayPackage(packagePath, policy.modulePath),
			covered: packageCoverage.covered,
			total:   packageCoverage.total,
			minimum: minimum,
			status:  status,
		})
		if packageCoverage.covered > math.MaxInt64-aggregate.covered || packageCoverage.total > math.MaxInt64-aggregate.total {
			result.problems = append(result.problems, "library aggregate statement count overflow")
			continue
		}
		aggregate.covered += packageCoverage.covered
		aggregate.total += packageCoverage.total
	}

	aggregateStatus := "PASS"
	if aggregate.total == 0 || !meetsMinimum(aggregate, policy.aggregateMinimum) {
		aggregateStatus = "FAIL"
	}
	result.results = append(result.results, coverageResult{
		name:    "library aggregate",
		covered: aggregate.covered,
		total:   aggregate.total,
		minimum: policy.aggregateMinimum,
		status:  aggregateStatus,
	})
	sort.Strings(result.problems)
	return result
}

func validatePolicy(policy coveragePolicy, evaluated *evaluation) {
	if policy.modulePath == "" {
		evaluated.problems = append(evaluated.problems, "coverage policy module path is empty")
	}
	if policy.defaultMinimum < 0 || policy.defaultMinimum > 100 {
		evaluated.problems = append(evaluated.problems, fmt.Sprintf("default minimum %d is outside 0..100", policy.defaultMinimum))
	}
	if policy.aggregateMinimum < 0 || policy.aggregateMinimum > 100 {
		evaluated.problems = append(evaluated.problems, fmt.Sprintf("aggregate minimum %d is outside 0..100", policy.aggregateMinimum))
	}
	for packagePath, minimum := range policy.packageMinimums {
		if minimum < 0 || minimum > 100 {
			evaluated.problems = append(evaluated.problems, fmt.Sprintf("package %q minimum %d is outside 0..100", packagePath, minimum))
		}
	}
}

func withinModule(packagePath, module string) bool {
	return packagePath == module || strings.HasPrefix(packagePath, module+"/")
}

func excludedPackage(packagePath, module string) bool {
	examples := module + "/examples"
	return packagePath == examples || strings.HasPrefix(packagePath, examples+"/")
}

func displayPackage(packagePath, module string) string {
	if packagePath == module {
		return "root"
	}
	return strings.TrimPrefix(packagePath, module+"/")
}

func meetsMinimum(coverage packageCoverage, minimum int64) bool {
	coveredHigh, coveredLow := bits.Mul64(uint64(coverage.covered), 100)
	minimumHigh, minimumLow := bits.Mul64(uint64(coverage.total), uint64(minimum))
	return coveredHigh > minimumHigh || (coveredHigh == minimumHigh && coveredLow >= minimumLow)
}

func writeEvaluation(output io.Writer, evaluated evaluation, policy coveragePolicy) {
	for _, result := range evaluated.results {
		if result.total == 0 {
			fmt.Fprintf(output, "%s %-20s %d/%d statements (minimum %d%%)\n", result.status, result.name, result.covered, result.total, result.minimum)
			continue
		}
		percentage := 100 * float64(result.covered) / float64(result.total)
		fmt.Fprintf(output, "%s %-20s %d/%d statements = %.2f%% (minimum %d%%)\n", result.status, result.name, result.covered, result.total, percentage, result.minimum)
	}
	for _, problem := range evaluated.problems {
		fmt.Fprintf(output, "ERROR %s\n", problem)
	}
	if len(evaluated.problems) == 0 {
		fmt.Fprintf(output, "Policy: future packages >= %d%%; examples excluded; aggregate >= %d%%\n", policy.defaultMinimum, policy.aggregateMinimum)
	}
}

func (e evaluation) failed() bool {
	if len(e.problems) != 0 {
		return true
	}
	for _, result := range e.results {
		if result.status == "FAIL" {
			return true
		}
	}
	return false
}
