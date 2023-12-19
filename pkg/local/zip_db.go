package local

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/anthony-zh/osv-proxy/pkg/local/semantic"
	"github.com/google/osv-scanner/pkg/lockfile"
	osvmodels "github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
)

type ZipDB struct {
	// the name of the database
	Name string
	// the path to the zip archive on disk
	StoredAt string
	// the vulnerabilities that are loaded into this database
	vulnerabilities []osvmodels.Vulnerability
}

var ErrOfflineDatabaseNotFound = errors.New("no offline version of the OSV database is available")

func (db *ZipDB) fetchZip() ([]byte, error) {
	cache, err := os.ReadFile(db.StoredAt)
	if err != nil {
		return nil, ErrOfflineDatabaseNotFound
	}

	return cache, nil

}

// Loads the given zip file into the database as an OSV.
// It is assumed that the file is JSON and in the working directory of the db
func (db *ZipDB) loadZipFile(zipFile *zip.File) {
	file, err := zipFile.Open()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Could not read %s: %v\n", zipFile.Name, err)

		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Could not read %s: %v\n", zipFile.Name, err)

		return
	}

	var vulnerability osvmodels.Vulnerability

	if err := json.Unmarshal(content, &vulnerability); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s is not a valid JSON file: %v\n", zipFile.Name, err)

		return
	}

	db.vulnerabilities = append(db.vulnerabilities, vulnerability)
}

// load fetches a zip archive of the OSV database and loads known vulnerabilities
// from it (which are assumed to be in json files following the OSV spec).
//
// Internally, the archive is cached along with the date that it was fetched
// so that a new version of the archive is only downloaded if it has been
// modified, per HTTP caching standards.
func (db *ZipDB) load() error {
	db.vulnerabilities = []osvmodels.Vulnerability{}

	body, err := db.fetchZip()

	if err != nil {
		return err
	}

	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return fmt.Errorf("could not read OSV database archive: %w", err)
	}

	// Read all the files from the zip archive
	for _, zipFile := range zipReader.File {
		if !strings.HasSuffix(zipFile.Name, ".json") {
			continue
		}

		db.loadZipFile(zipFile)
	}

	return nil
}
func toPackageDetails(query *osv.Query) (lockfile.PackageDetails, error) {
	if query.Package.PURL != "" {
		pkg, err := osvmodels.PURLToPackage(query.Package.PURL)

		if err != nil {
			return lockfile.PackageDetails{}, err
		}

		return lockfile.PackageDetails{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: lockfile.Ecosystem(pkg.Ecosystem),
			CompareAs: lockfile.Ecosystem(pkg.Ecosystem),
		}, nil
	}

	return lockfile.PackageDetails{
		Name:      query.Package.Name,
		Version:   query.Version,
		Commit:    query.Commit,
		Ecosystem: lockfile.Ecosystem(query.Package.Ecosystem),
		CompareAs: lockfile.Ecosystem(query.Package.Ecosystem),
	}, nil
}

// https://osv-vulnerabilities.storage.googleapis.com/{:ecosystem}/all.zip
func NewZippedDB(dbBasePath, name string) (*ZipDB, error) {
	db := &ZipDB{
		Name:     name,
		StoredAt: path.Join(dbBasePath, name, "all.zip"),
	}
	if err := db.load(); err != nil {
		return nil, fmt.Errorf("unable to fetch OSV database: %w", err)
	}

	return db, nil
}

func (db *ZipDB) Vulnerabilities(includeWithdrawn bool) []osvmodels.Vulnerability {
	if includeWithdrawn {
		return db.vulnerabilities
	}

	var vulnerabilities []osvmodels.Vulnerability

	for _, vulnerability := range db.vulnerabilities {
		if vulnerability.Withdrawn.IsZero() {
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return vulnerabilities
}

func eventVersion(e osvmodels.Event) string {
	if e.Introduced != "" {
		return e.Introduced
	}

	if e.Fixed != "" {
		return e.Fixed
	}

	if e.Limit != "" {
		return e.Limit
	}

	if e.LastAffected != "" {
		return e.LastAffected
	}

	return ""
}

func rangeContainsVersion(ar osvmodels.Range, pkg lockfile.PackageDetails) bool {
	if ar.Type != osvmodels.RangeEcosystem && ar.Type != osvmodels.RangeSemVer {
		return false
	}
	// todo: we should probably warn here
	if len(ar.Events) == 0 {
		return false
	}

	vp := semantic.MustParse(pkg.Version, pkg.CompareAs)

	sort.Slice(ar.Events, func(i, j int) bool {
		a := ar.Events[i]
		b := ar.Events[j]

		if a.Introduced == "0" {
			return true
		}

		if b.Introduced == "0" {
			return false
		}

		return semantic.MustParse(eventVersion(a), pkg.CompareAs).CompareStr(eventVersion(b)) < 0
	})

	var affected bool
	for _, e := range ar.Events {
		if affected {
			if e.Fixed != "" {
				affected = vp.CompareStr(e.Fixed) < 0
			} else if e.LastAffected != "" {
				affected = e.LastAffected == pkg.Version || vp.CompareStr(e.LastAffected) <= 0
			}
		} else if e.Introduced != "" {
			affected = e.Introduced == "0" || vp.CompareStr(e.Introduced) >= 0
		}
	}

	return affected
}

// rangeAffectsVersion checks if the given version is within the range
// specified by the events of any "Ecosystem" or "Semver" type ranges
func rangeAffectsVersion(a []osvmodels.Range, pkg lockfile.PackageDetails) bool {
	for _, r := range a {
		if r.Type != osvmodels.RangeEcosystem && r.Type != osvmodels.RangeSemVer {
			return false
		}
		if rangeContainsVersion(r, pkg) {
			return true
		}
	}

	return false
}

func isAliasOfID(v osvmodels.Vulnerability, id string) bool {
	for _, alias := range v.Aliases {
		if alias == id {
			return true
		}
	}

	return false
}

func isAliasOf(v osvmodels.Vulnerability, vulnerability osvmodels.Vulnerability) bool {
	for _, alias := range vulnerability.Aliases {
		if v.ID == alias || isAliasOfID(v, alias) {
			return true
		}
	}

	return false
}
func Include(vs osvmodels.Vulnerabilities, vulnerability osvmodels.Vulnerability) bool {
	for _, vuln := range vs {
		if vuln.ID == vulnerability.ID {
			return true
		}

		if isAliasOf(vuln, vulnerability) {
			return true
		}
		if isAliasOf(vulnerability, vuln) {
			return true
		}
	}

	return false
}

func IsAffected(v osvmodels.Vulnerability, pkg lockfile.PackageDetails) bool {
	for _, affected := range v.Affected {
		if string(affected.Package.Ecosystem) == string(pkg.Ecosystem) &&
			affected.Package.Name == pkg.Name {
			if len(affected.Ranges) == 0 && len(affected.Versions) == 0 {
				_, _ = fmt.Fprintf(
					os.Stderr,
					"%s does not have any ranges or versions - this is probably a mistake!\n",
					v.ID,
				)

				continue
			}

			if slices.Contains(affected.Versions, pkg.Version) {
				return true
			}

			if rangeAffectsVersion(affected.Ranges, pkg) {
				return true
			}

			// if a package does not have a version, assume it is vulnerable
			// as false positives are better than false negatives here
			if pkg.Version == "" {
				return true
			}
		}
	}

	return false
}

func (db *ZipDB) VulnerabilitiesAffectingPackage(pkg lockfile.PackageDetails) osvmodels.Vulnerabilities {
	var vulnerabilities osvmodels.Vulnerabilities

	for _, vulnerability := range db.Vulnerabilities(false) {
		if IsAffected(vulnerability, pkg) && !Include(vulnerabilities, vulnerability) {
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return vulnerabilities
}

func (db *ZipDB) Check(pkgs []lockfile.PackageDetails) (osvmodels.Vulnerabilities, error) {
	vulnerabilities := make(osvmodels.Vulnerabilities, 0, len(pkgs))

	for _, pkg := range pkgs {
		vulnerabilities = append(vulnerabilities, db.VulnerabilitiesAffectingPackage(pkg)...)
	}

	return vulnerabilities, nil
}
