package local

import (
	"fmt"

	"log"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
)

func MakeRequest(query osv.BatchedQuery, dbBasePath string) (*osv.HydratedBatchedResponse, error) {
	results := make([]osv.Response, 0, len(query.Queries))
	dbs := make(map[lockfile.Ecosystem]*ZipDB)

	loadDBFromCache := func(ecosystem lockfile.Ecosystem) (*ZipDB, error) {
		if db, ok := dbs[ecosystem]; ok {
			return db, nil
		}
		db, err := NewZippedDB(dbBasePath, string(ecosystem))
		if err != nil {
			return nil, err
		}
		log.Printf("Loaded %s local db from %s\n", db.Name, db.StoredAt)
		dbs[ecosystem] = db
		return db, nil
	}

	for _, query := range query.Queries {
		pkg, err := ToPackageDetails(query)

		if err != nil {
			// currently, this will actually only error if the PURL cannot be parses
			log.Printf("skipping %s as it is not a valid PURL: %v\n", query.Package.PURL, err)
			results = append(results, osv.Response{Vulns: []models.Vulnerability{}})
			continue
		}

		if pkg.Ecosystem == "" {
			if pkg.Commit == "" {
				// The only time this can happen should be when someone passes in their own OSV-Scanner-Results file.
				return nil, fmt.Errorf("ecosystem is empty and there is no commit hash")
			}

			// Is a commit based query, skip local scanning
			results = append(results, osv.Response{})
			log.Printf("Skipping commit scanning for: %s\n", pkg.Commit)

			continue
		}

		db, err := loadDBFromCache(pkg.Ecosystem)

		if err != nil {
			// currently, this will actually only error if the PURL cannot be parses
			log.Printf("could not load db for %s ecosystem: %v\n", pkg.Ecosystem, err)
			results = append(results, osv.Response{Vulns: []models.Vulnerability{}})

			continue
		}

		results = append(results, osv.Response{Vulns: db.VulnerabilitiesAffectingPackage(pkg)})
	}

	return &osv.HydratedBatchedResponse{Results: results}, nil
}
