package awx

import (
	"context"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	awx "github.com/mrcrilly/goawx/client"
	"strconv"
)

func dataSourceExecutionEnvironmentByName() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceExecutionEnvironmentsRead,
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
		},
	}
}

func dataSourceExecutionEnvironmentsRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
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

	executionEnvironments, _, err := client.ExecutionEnvironmentsService.ListExecutionEnvironments(map[string]string{})

	if err != nil {
		return buildDiagnosticsMessage(
			"Get: Fail to fetch Execution Environment list",
			"Fail to find the Execution Environment list, got: %s",
			err)
	}

	for _, executionEnvironment := range executionEnvironments {
		if executionEnvironment.Name == params["name"] {
			d.SetId(strconv.Itoa(executionEnvironment.ID))
			d.Set("name", executionEnvironment.Name)
			return diags
		}
	}

	return buildDiagnosticsMessage(
		"Execution Environment not found",
		"Could not find Execution Environment with name: %s",
		params["name"])
}