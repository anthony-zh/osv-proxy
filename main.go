package main

import "github.com/anthony-zh/osv-proxy/pkg/scan"

func main() {

	o := scan.NewOSVScaner(scan.OSVScanerOpt{})
	o.Query()

}
