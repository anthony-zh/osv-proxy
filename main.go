package main

import (
	"encoding/json"
	"fmt"

	"github.com/anthony-zh/osv-proxy/pkg/local"
	"github.com/anthony-zh/osv-proxy/pkg/scan"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
)

func main() {

	bType := false
	if bType {
		o := scan.NewOSVScaner(scan.OSVScanerOpt{
			DbPath: "E:\\workspace\\gitea-ee\\osv-server\\data\\osvdbs\\zh",
		})
		VulnId := "GHSA-67hx-6x53-jw92"
		vulnInfo := o.QueryVulnId(VulnId)
		fmt.Println("VulnId:", VulnId, "result:", vulnInfo)

		data := `{
			"queries": [
				{
					"commit": "0454aac03d8cd224d39b5dbba7badae8390b239f",
					"package": {}
				},
				{
					"package": {
						"name": "@ampproject/remapping",
						"ecosystem": "npm"
					},
					"version": "2.2.0"
				},
				{
					"package": {
						"name": "@antv/event-emitter",
						"ecosystem": "npm"
					},
					"version": "0.1.3"
				}
			]
		}`
		batch := &osv.BatchedQuery{}
		json.Unmarshal([]byte(data), batch)
		res := o.QueryBatch(batch)
		fmt.Println("Batch:", VulnId, "result:", res)
	}

	data2 := `{
		"package": {
			"ecosystem": "Go",
			"name": "github.com/containerd/containerd",
			"purl": "pkg:golang/github.com/containerd/containerd"
		},
		"ranges": [
			{
				"type": "SEMVER",
				"events": [
					{
						"introduced": "1.7.0"
					},
					{
						"fixed": "1.7.11"
					}
				]
			}
		],
		"database_specific": {
			"last_known_affected_version_range": "<= 1.7.10",
			"source": "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2023/12/GHSA-7ww5-4wqc-m92c/GHSA-7ww5-4wqc-m92c.json"
		}
	}`
	affected := &models.Affected{}
	json.Unmarshal([]byte(data2), affected)
	ver, b := local.GetFixedVersion(affected, lockfile.PackageDetails{
		Name:      "github.com/containerd/containerd",
		Version:   "1.7.3",
		Ecosystem: lockfile.Ecosystem("Go"),
		CompareAs: lockfile.Ecosystem("Go"),
	})
	fmt.Println("-->", ver, b)
}
