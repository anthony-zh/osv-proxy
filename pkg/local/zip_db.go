package local

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/anthony-zh/osv-proxy/pkg/local/semantic"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
)

type ZipDB struct {
	// the name of the database
	Name string
	// the path to the zip archive on disk
	StoredAt string
	// the vulnerabilities that are loaded into this database
	vulnerabilities []models.Vulnerability
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

	var vulnerability models.Vulnerability

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
	db.vulnerabilities = []models.Vulnerability{}

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

func (db *ZipDB) Add(vulner *models.Vulnerability) {
	if db.vulnerabilities == nil {
		db.vulnerabilities = make([]models.Vulnerability, 0)
	}
	for _, v := range db.vulnerabilities {
		if v.ID == vulner.ID {
			return
		}
	}
	db.vulnerabilities = append(db.vulnerabilities, *vulner)
}

func (db *ZipDB) Iterates(call func(index int, vulner *models.Vulnerability) bool) bool {
	for k := range db.vulnerabilities {
		if !call(k, &db.vulnerabilities[k]) {
			return false
		}
	}
	return true
}
func ToPackageDetails(query *osv.Query) (lockfile.PackageDetails, error) {
	if query.Package.PURL != "" {
		pkg, err := models.PURLToPackage(query.Package.PURL)

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
		StoredAt: filepath.Join(dbBasePath, name, "all.zip"),
	}
	if err := db.load(); err != nil {
		return nil, fmt.Errorf("unable to fetch OSV database: %w", err)
	}

	return db, nil
}

func (db *ZipDB) Vulnerabilities(includeWithdrawn bool) []models.Vulnerability {
	if includeWithdrawn {
		return db.vulnerabilities
	}

	var vulnerabilities []models.Vulnerability

	for _, vulnerability := range db.vulnerabilities {
		if vulnerability.Withdrawn.IsZero() {
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return vulnerabilities
}

func eventVersion(e models.Event) string {
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

func rangeContainsVersion(ar models.Range, pkg lockfile.PackageDetails) (string, bool) {
	if ar.Type != models.RangeEcosystem && ar.Type != models.RangeSemVer {
		return "", false
	}
	// todo: we should probably warn here
	if len(ar.Events) == 0 {
		return "", false
	}

	vp, err := semantic.Parse(pkg.Version, pkg.CompareAs)
	if err != nil {
		return "", false
	}

	sort.Slice(ar.Events, func(i, j int) bool {
		a := ar.Events[i]
		b := ar.Events[j]

		if a.Introduced == "0" {
			return true
		}

		if b.Introduced == "0" {
			return false
		}
		vp1, err := semantic.Parse(eventVersion(a), pkg.CompareAs)
		if err != nil {
			return false
		}
		return vp1.CompareStr(eventVersion(b)) < 0
	})

	var affected bool
	var version = ""
	for _, e := range ar.Events {
		if affected {
			if e.Fixed != "" {
				affected = vp.CompareStr(e.Fixed) < 0
				if affected {
					version = e.Fixed
				}
			} else if e.LastAffected != "" {
				affected = e.LastAffected == pkg.Version || vp.CompareStr(e.LastAffected) <= 0
				if affected {
					version = e.Fixed
				}
			}
		} else if e.Introduced != "" {
			affected = e.Introduced == "0" || vp.CompareStr(e.Introduced) >= 0
			if affected {
				version = e.Fixed
			}
		}
	}

	return version, affected
}

// rangeAffectsVersion checks if the given version is within the range
// specified by the events of any "Ecosystem" or "Semver" type ranges
func rangeAffectsVersion(a []models.Range, pkg lockfile.PackageDetails) bool {
	for _, r := range a {
		if r.Type != models.RangeEcosystem && r.Type != models.RangeSemVer {
			return false
		}
		if _, b := rangeContainsVersion(r, pkg); b {
			return true
		}
	}

	return false
}

func isAliasOfID(v models.Vulnerability, id string) bool {
	for _, alias := range v.Aliases {
		if alias == id {
			return true
		}
	}

	return false
}

func isAliasOf(v models.Vulnerability, vulnerability models.Vulnerability) bool {
	for _, alias := range vulnerability.Aliases {
		if v.ID == alias || isAliasOfID(v, alias) {
			return true
		}
	}

	return false
}

var (
	IgnoreAlias = false
)

func Include(vs models.Vulnerabilities, vulnerability models.Vulnerability) bool {
	for _, vuln := range vs {
		if vuln.ID == vulnerability.ID {
			return true
		}

		//  这里主要是去掉漏洞号不同，其它一样的漏洞信息
		if !IgnoreAlias {
			if isAliasOf(vuln, vulnerability) {
				return true
			}
			if isAliasOf(vulnerability, vuln) {
				return true
			}
		}

	}

	return false
}

func GetFixedVersion(affected *models.Affected, pkg lockfile.PackageDetails) (string, bool) {
	if len(affected.Package.Name) > 0 && affected.Package.Name != pkg.Name {
		return "", false
	}
	////////////////////////////////////////////////////
	for _, r := range affected.Ranges {
		if r.Type != models.RangeEcosystem && r.Type != models.RangeSemVer {
			continue
		}
		if ver, b := rangeContainsVersion(r, pkg); b {
			return ver, true
		}
	}

	return "", false
}

func IsAffected(v models.Vulnerability, pkg lockfile.PackageDetails) (bool, bool) {
	bHere := false
	for _, affected := range v.Affected {
		if string(affected.Package.Ecosystem) == string(pkg.Ecosystem) &&
			affected.Package.Name == pkg.Name {
			bHere = true
			if len(affected.Ranges) == 0 && len(affected.Versions) == 0 {
				_, _ = fmt.Fprintf(
					os.Stderr,
					"%s does not have any ranges or versions - this is probably a mistake!\n",
					v.ID,
				)

				continue
			}

			if slices.Contains(affected.Versions, pkg.Version) {
				return bHere, true
			}

			if rangeAffectsVersion(affected.Ranges, pkg) {
				return bHere, true
			}

			// if a package does not have a version, assume it is vulnerable
			// as false positives are better than false negatives here
			if pkg.Version == "" {
				return bHere, true
			}
		}
	}

	return bHere, false
}
func (db *ZipDB) VulnerabilitiesAffectingPackage(pkg lockfile.PackageDetails) models.Vulnerabilities {
	var vulnerabilities models.Vulnerabilities

	for _, vulnerability := range db.Vulnerabilities(false) {
		_, b2 := IsAffected(vulnerability, pkg)
		if b2 {
			if !Include(vulnerabilities, vulnerability) {
				vulnerabilities = append(vulnerabilities, vulnerability)
			}
		}
	}

	return vulnerabilities
}
func (db *ZipDB) VulnerabilitiesAffectingPackage2(pkg lockfile.PackageDetails) (models.Vulnerabilities, bool) {
	var vulnerabilities models.Vulnerabilities
	bHere := false
	for _, vulnerability := range db.Vulnerabilities(false) {
		b1, b2 := IsAffected(vulnerability, pkg)
		if b1 {
			bHere = true
		}
		if b2 {
			if !Include(vulnerabilities, vulnerability) {
				vulnerabilities = append(vulnerabilities, vulnerability)
			}
		}
	}

	return vulnerabilities, bHere
}

func (db *ZipDB) Check(pkgs []lockfile.PackageDetails) (models.Vulnerabilities, error) {
	vulnerabilities := make(models.Vulnerabilities, 0, len(pkgs))

	for _, pkg := range pkgs {
		vulnerabilities = append(vulnerabilities, db.VulnerabilitiesAffectingPackage(pkg)...)
	}

	return vulnerabilities, nil
}
