package awx

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	awx "github.com/denouche/goawx/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"hostname": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("AWX_HOSTNAME", "http://localhost"),
			},
			"insecure": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Disable SSL verification of API calls",
			},
			"username": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("AWX_USERNAME", "admin"),
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("AWX_PASSWORD", "password"),
			},
			"token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("AWX_TOKEN", ""),
			},
			"client_cert": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Client certificate to use for mTLS validation. Must be provided along with client-key and ca-cert for mTLS to be used.",
			},
			"client_key": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Client key to use for mTLS validation. Must be provided along with client-cert and ca-cert for mTLS to be used",
			},
			"ca_cert": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: "CA certificate to use for mTLS validation. Must be provided along with client-cert and client-key for mTLS to be used",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"awx_credential_azure_key_vault":                          resourceCredentialAzureKeyVault(),
			"awx_credential_google_compute_engine":                    resourceCredentialGoogleComputeEngine(),
			"awx_credential_input_source":                             resourceCredentialInputSource(),
			"awx_credential":                                          resourceCredential(),
			"awx_credential_type":                                     resourceCredentialType(),
			"awx_credential_machine":                                  resourceCredentialMachine(),
			"awx_credential_scm":                                      resourceCredentialSCM(),
			"awx_credential_gitlab":                                   resourceCredentialGitlab(),
			"awx_credential_galaxy":                                   resourceCredentialGalaxy(),
			"awx_execution_environment":                               resourceExecutionEnvironment(),
			"awx_host":                                                resourceHost(),
			"awx_instance_group":                                      resourceInstanceGroup(),
			"awx_inventory_group":                                     resourceInventoryGroup(),
			"awx_inventory_source":                                    resourceInventorySource(),
			"awx_inventory":                                           resourceInventory(),
			"awx_job_template_credential":                             resourceJobTemplateCredentials(),
			"awx_job_template":                                        resourceJobTemplate(),
			"awx_job_template_launch":                                 resourceJobTemplateLaunch(),
			"awx_job_template_notification_template_error":            resourceJobTemplateNotificationTemplateError(),
			"awx_job_template_notification_template_started":          resourceJobTemplateNotificationTemplateStarted(),
			"awx_job_template_notification_template_success":          resourceJobTemplateNotificationTemplateSuccess(),
			"awx_notification_template":                               resourceNotificationTemplate(),
			"awx_organization":                                        resourceOrganization(),
			"awx_organization_galaxy_credential":                      resourceOrganizationsGalaxyCredentials(),
			"awx_project":                                             resourceProject(),
			"awx_schedule":                                            resourceSchedule(),
			"awx_settings_ldap_team_map":                              resourceSettingsLDAPTeamMap(),
			"awx_setting":                                             resourceSetting(),
			"awx_team":                                                resourceTeam(),
			"awx_user":                                                resourceUser(),
			"awx_workflow_job_template_node_always":                   resourceWorkflowJobTemplateNodeAlways(),
			"awx_workflow_job_template_node_failure":                  resourceWorkflowJobTemplateNodeFailure(),
			"awx_workflow_job_template_node_success":                  resourceWorkflowJobTemplateNodeSuccess(),
			"awx_workflow_job_template_node":                          resourceWorkflowJobTemplateNode(),
			"awx_workflow_job_template":                               resourceWorkflowJobTemplate(),
			"awx_workflow_job_template_schedule":                      resourceWorkflowJobTemplateSchedule(),
			"awx_workflow_job_template_notification_template_error":   resourceWorkflowJobTemplateNotificationTemplateError(),
			"awx_workflow_job_template_notification_template_started": resourceWorkflowJobTemplateNotificationTemplateStarted(),
			"awx_workflow_job_template_notification_template_success": resourceWorkflowJobTemplateNotificationTemplateSuccess(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"awx_credential_azure_key_vault": dataSourceCredentialAzure(),
			"awx_credential":                 dataSourceCredentialByName(),
			"awx_execution_environment":      dataSourceExecutionEnvironmentByName(),
			"awx_inventory_group":            dataSourceInventoryGroup(),
			"awx_inventory":                  dataSourceInventory(),
			"awx_inventory_role":             dataSourceInventoryRole(),
			"awx_job_template":               dataSourceJobTemplate(),
			"awx_notification_template":      dataSourceNotificationTemplate(),
			"awx_organization":               dataSourceOrganization(),
			"awx_organization_role":          dataSourceOrganizationRole(),
			"awx_organizations":              dataSourceOrganizations(),
			"awx_project":                    dataSourceProject(),
			"awx_project_role":               dataSourceProjectRole(),
			"awx_schedule":                   dataSourceSchedule(),
			"awx_workflow_job_template":      dataSourceWorkflowJobTemplate(),
			"awx_team":                       dataSourceTeam(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	hostname := d.Get("hostname").(string)
	username := d.Get("username").(string)
	password := d.Get("password").(string)
	token := d.Get("token").(string)
	clientCertPEM, clientCertPEMExists := d.GetOk("client_cert")
	clientKeyPEM, clientKeyPEMExists := d.GetOk("client_key")
	caCertPEM, caCertPEMExists := d.GetOk("ca_cert")

	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics

	client := http.DefaultClient
	if d.Get("insecure").(bool) {
		customTransport := http.DefaultTransport.(*http.Transport).Clone()
		customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		client.Transport = customTransport
		} else if clientCertPEMExists && clientKeyPEMExists && caCertPEMExists {
			transportTlsConfig, err := generateMtlsConfig(
				clientCertPEM.(string),
				clientKeyPEM.(string),
				caCertPEM.(string))
	
			if err == nil {
				client.Transport = &http.Transport{
					TLSClientConfig: transportTlsConfig,
				}
			} else {
				var diags diag.Diagnostics
				return nil, append(diags, diag.Diagnostic{
					Severity: diag.Error,
					Summary:  "Invalid mTLS config",
					Detail:   fmt.Sprintf("The provided mTLS config is invalid: %s", err),
				})
			}
	}

	var c *awx.AWX
	var err error
	if token != "" {
		c, err = awx.NewAWXToken(hostname, token, client)
	} else {
		c, err = awx.NewAWX(hostname, username, password, client)
	}
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to create AWX client",
			Detail:   "Unable to auth user against AWX API: check the hostname, username and password",
		})
		return nil, diags
	}

	return c, diags
}

// This method also writes the mTLS certificates to disk - to allow them to be used for other calls to
// AWX
func generateMtlsConfig(clientCertPEM string, clientKeyPEM string, caCertPEM string) (*tls.Config, error) {
	clientCertPEMBlock := []byte(clientCertPEM)
	clientKeyPEMBlock := []byte(clientKeyPEM)
	caCertPEMBlock := []byte(caCertPEM)

	tempCertificatePath := "/wrk/terraform-provider-awx"
	os.MkdirAll(tempCertificatePath, 0700)

	writeByteArrayToFile(clientCertPEMBlock, filepath.Join(tempCertificatePath, "tls.crt"))
	writeByteArrayToFile(clientKeyPEMBlock, filepath.Join(tempCertificatePath, "tls.key"))
	writeByteArrayToFile(caCertPEMBlock, filepath.Join(tempCertificatePath, "ca.crt"))

	cert, err := tls.X509KeyPair(clientCertPEMBlock, clientKeyPEMBlock)
	if err != nil {
		return nil, err
	}

	caCertPool, _ := x509.SystemCertPool()
	if caCertPool == nil {
		caCertPool = x509.NewCertPool()
	}
	caCertPool.AppendCertsFromPEM(caCertPEMBlock)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}, nil
}

func writeByteArrayToFile(byteArray []byte, filePath string) {
	t, err := os.Create(filePath)
	if err == nil {
		t.Write(byteArray)
		t.Close()
	}
}