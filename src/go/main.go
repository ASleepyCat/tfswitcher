package main

import (
	"C"

	"github.com/hashicorp/terraform-config-inspect/tfconfig"
)

//export GetVersionFromModule
func GetVersionFromModule() *C.char {
	module, diag := tfconfig.LoadModule(".")
	if diag.HasErrors() {
		return nil
	}

	versionConstraint := module.RequiredCore[0]
	return C.CString(versionConstraint)
}

func main() {}
