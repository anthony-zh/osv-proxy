package scan

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/anthony-zh/osv-proxy/pkg/local"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
)

type OSVScanerOpt struct {
	DbPath      string
	IgnoreAlias bool
}
type OSVScaner struct {
	localDbPath     string
	lock            sync.RWMutex
	dbs             map[lockfile.Ecosystem]*local.ZipDB
	vulnerabilities map[string]*models.Vulnerability
}

func (s *OSVScaner) Load(dbPath string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.dbs = make(map[lockfile.Ecosystem]*local.ZipDB)
	s.vulnerabilities = make(map[string]*models.Vulnerability)
	s.localDbPath = dbPath
	fs, err := os.ReadDir(s.localDbPath)
	if err != nil {
		return err
	}
	loadDBFromCache := func(ecosystem lockfile.Ecosystem) error {
		if _, ok := s.dbs[ecosystem]; ok {
			return nil
		}
		db, err := local.NewZippedDB(s.localDbPath, string(ecosystem))
		if err != nil {
			return err
		}
		log.Printf("Loaded %s local db from %s\n", db.Name, db.StoredAt)
		s.dbs[ecosystem] = db
		return nil
	}
	for _, v := range fs {
		if !v.IsDir() {
			continue
		}
		loadDBFromCache(lockfile.Ecosystem(v.Name()))
	}
	////////////////////////////////////////////////////////
	for _, v := range s.dbs {
		v.Iterates(func(index int, vulner *models.Vulnerability) bool {
			s.vulnerabilities[vulner.ID] = vulner
			return true
		})
	}
	if len(s.vulnerabilities) == 0 {
		return fmt.Errorf("not vulnerabilitie db")
	}
	return nil
}

func (s *OSVScaner) Iterates(call func(name lockfile.Ecosystem, index int, vulner *models.Vulnerability) bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	if s.dbs == nil {
		return
	}
	for k, v := range s.dbs {
		if !v.Iterates(func(index int, vulner *models.Vulnerability) bool {
			return call(k, index, vulner)
		}) {
			break
		}
	}
}
func (s *OSVScaner) QueryBatch(o *osv.BatchedQuery, call func(query *osv.Query, pkg lockfile.PackageDetails) models.Vulnerabilities) *osv.BatchedResponse {
	s.lock.RLock()
	defer s.lock.RUnlock()
	if s.dbs == nil {
		return nil
	}

	results := osv.BatchedResponse{
		Results: make([]osv.MinimalResponse, len(o.Queries)),
	}
	for k, query := range o.Queries {
		pkg, err := local.ToPackageDetails(query)
		if err != nil {
			// currently, this will actually only error if the PURL cannot be parses
			log.Printf("skipping %s as it is not a valid PURL: %v\n", query.Package.PURL, err)
			continue
		}
		if pkg.Ecosystem == "" {
			if pkg.Commit == "" {
				// The only time this can happen should be when someone passes in their own OSV-Scanner-Results file.
				continue
			}
			// Is a commit based query, skip local scanning
			log.Printf("Skipping commit scanning for: %s\n", pkg.Commit)
			continue
		}
		if db, ok := s.dbs[pkg.Ecosystem]; ok {
			vulns, bHas := db.VulnerabilitiesAffectingPackage2(pkg)
			arr := make([]osv.MinimalVulnerability, 0)
			if !bHas && len(vulns) == 0 && call != nil {
				vulns = call(query, pkg)
			}
			if len(vulns) > 0 {
				for _, v1 := range vulns {
					arr = append(arr, osv.MinimalVulnerability{
						ID: v1.ID,
					})
				}
			}
			results.Results[k] = osv.MinimalResponse{
				Vulns: arr,
			}
		}
	}
	return &results
}
func (s *OSVScaner) AddVulnId(o *models.Vulnerability) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.vulnerabilities == nil {
		return
	}
	s.vulnerabilities[o.ID] = o
	for _, v := range o.Affected {
		if vv, ok := s.dbs[lockfile.Ecosystem(v.Package.Ecosystem)]; ok {
			vv.Add(o)
		} else {
			zipDb := &local.ZipDB{
				Name: string(v.Package.Ecosystem),
			}
			zipDb.Add(o)
			s.dbs[lockfile.Ecosystem(v.Package.Ecosystem)] = zipDb
		}
	}
}
func (s *OSVScaner) QueryVulnId(vulnId string) *models.Vulnerability {
	s.lock.RLock()
	defer s.lock.RUnlock()
	if s.vulnerabilities == nil {
		return nil
	}
	if vv, ok := s.vulnerabilities[vulnId]; ok {
		return vv
	}
	return nil
}

func (s *OSVScaner) DoSacn(ctx context.Context, file lockfile.Lockfile, compareLocally bool) ([]models.Vulnerability, error) {
	var query osv.BatchedQuery
	for _, p := range file.Packages {
		query.Queries = append(query.Queries, osv.MakePkgRequest(lockfile.PackageDetails{
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: p.Ecosystem,
			CompareAs: p.CompareAs,
		}))
	}

	call := func(r *osv.HydratedBatchedResponse) []models.Vulnerability {
		res := make([]models.Vulnerability, 0)
		for _, v := range r.Results {
			if len(v.Vulns) > 0 {
				res = append(res, v.Vulns...)
			}
		}
		return res
	}

	if compareLocally {
		s.lock.RLock()
		defer s.lock.RUnlock()
		if s.dbs == nil {
			return nil, fmt.Errorf("not init dbs")
		}

		results := make([]osv.Response, 0, len(query.Queries))
		for _, query := range query.Queries {
			pkg, err := local.ToPackageDetails(query)
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
			if db, ok := s.dbs[pkg.Ecosystem]; ok {
				results = append(results, osv.Response{Vulns: db.VulnerabilitiesAffectingPackage(pkg)})
			}

		}
		hydratedResp := &osv.HydratedBatchedResponse{Results: results}
		return call(hydratedResp), nil
	}
	// resp, err := osv.MakeRequestWithClient(query, client)
	// if err != nil {
	// 	return nil, err
	// }
	// hydratedResp, err := osv.HydrateWithClient(resp, client)
	resp, err := osv.MakeRequest(query)
	if err != nil {
		return nil, err
	}
	hydratedResp, err := osv.Hydrate(resp)
	if err != nil {
		return nil, err
	}
	return call(hydratedResp), nil
}

func FindLockfiles(filePath string) (*lockfile.Lockfile, error) {

	p, parseAs := lockfile.FindExtractor(filePath, "")
	if p != nil {
		f, err := lockfile.OpenLocalDepFile(filePath)
		if err != nil {
			return nil, err
		}
		parsedLockfile, err := lockfile.ExtractDeps(f, parseAs)
		f.Close()
		if err != nil {
			return nil, err
		}
		return &parsedLockfile, nil
	}
	return nil, fmt.Errorf("Not Supported")
}

func NewOSVScaner(opt OSVScanerOpt) *OSVScaner {
	o := OSVScaner{}
	if err := o.Load(opt.DbPath); err != nil {
		return nil
	}
	local.IgnoreAlias = opt.IgnoreAlias
	return &o
}
