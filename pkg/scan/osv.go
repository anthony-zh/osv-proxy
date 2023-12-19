package scan

import (
	"context"
	"fmt"

	"github.com/anthony-zh/osv-proxy/pkg/local"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
)

type OSVScanerOpt struct {
}
type OSVScaner struct {
	compareLocally bool
	localDbPath    string
}

func (s *OSVScaner) Query() {

}

func (s *OSVScaner) DoSacn(ctx context.Context, file lockfile.Lockfile) ([]models.Vulnerability, error) {
	var query osv.BatchedQuery
	for _, p := range file.Packages {
		query.Queries = append(query.Queries, osv.MakePkgRequest(lockfile.PackageDetails{
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: p.Ecosystem,
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

	if s.compareLocally {
		hydratedResp, err := local.MakeRequest(query, s.localDbPath)
		if err != nil {
			return nil, fmt.Errorf("scan failed %w", err)
		}

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

func NewOSVScaner(opt OSVScanerOpt) *OSVScaner {

	return nil
}
