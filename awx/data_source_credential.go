/*
Use this data source to query Credential by ID.

Example Usage

```hcl
*TBD*
```

*/
package awx

import (
	"context"
	"strconv"

	awx "github.com/denouche/goawx/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceCredentialByName() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceCredentialsRead,
		Schema: map[string]*schema.Schema{
			"id": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
				Computed: true,
			},
			"name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
				Computed: false,
			},
			"kind": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
		},
	}
}

func dataSourceCredentialsRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	client := m.(*awx.AWX)
	params := make(map[string]string)

	if name, okName := d.GetOk("name"); okName {
		params["name"] = name.(string)
	}

	if len(params) == 0 {
		return buildDiagnosticsMessage(
			"Get: Missing Parameters",
			"Please use the selector: (name)")
	}

	credentials, err := client.CredentialsService.ListCredentials(map[string]string{})

	if err != nil {
		return buildDiagnosticsMessage(
			"Get: Fail to fetch Credential list",
			"Fail to find the Credential list, got: %s",
			err)
	}

	for _, credential := range credentials {
		if credential.Name == params["name"] {
			d.SetId(strconv.Itoa(credential.ID))
			d.Set("name", credential.Name)
			d.Set("kind", credential.Kind)
			return diags
		}
	}

	return buildDiagnosticsMessage(
		"Credential not found",
		"Could not find Credential with name: %s",
		params["name"])
}
