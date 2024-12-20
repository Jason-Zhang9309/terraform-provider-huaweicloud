// Generated by PMS #412
package dds

import (
	"context"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/tidwall/gjson"

	"github.com/huaweicloud/terraform-provider-huaweicloud/huaweicloud/config"
	"github.com/huaweicloud/terraform-provider-huaweicloud/huaweicloud/helper/httphelper"
	"github.com/huaweicloud/terraform-provider-huaweicloud/huaweicloud/helper/schemas"
)

func DataSourceDdsSslCertDownloadLinks() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceDdsSslCertDownloadLinksRead,

		Schema: map[string]*schema.Schema{
			"region": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: `Specifies the region in which to query the resource. If omitted, the provider-level region will be used.`,
			},
			"instance_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: `Specifies the instance ID.`,
			},
			"certs": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: `Indicates the certificate list.`,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"download_link": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: `Indicates the certificate download link.`,
						},
						"category": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: `Indicates the certificate type.`,
						},
					},
				},
			},
		},
	}
}

type SslCertDownloadLinksDSWrapper struct {
	*schemas.ResourceDataWrapper
	Config *config.Config
}

func newSslCertDownloadLinksDSWrapper(d *schema.ResourceData, meta interface{}) *SslCertDownloadLinksDSWrapper {
	return &SslCertDownloadLinksDSWrapper{
		ResourceDataWrapper: schemas.NewSchemaWrapper(d),
		Config:              meta.(*config.Config),
	}
}

func dataSourceDdsSslCertDownloadLinksRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	wrapper := newSslCertDownloadLinksDSWrapper(d, meta)
	lisSslCerDowAddRst, err := wrapper.ListSslCertDownloadAddress()
	if err != nil {
		return diag.FromErr(err)
	}

	err = wrapper.listSslCertDownloadAddressToSchema(lisSslCerDowAddRst)
	if err != nil {
		return diag.FromErr(err)
	}

	id, err := uuid.GenerateUUID()
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(id)
	return nil
}

// @API DDS GET /v3/{project_id}/instances/{instance_id}/ssl-cert/download-link
func (w *SslCertDownloadLinksDSWrapper) ListSslCertDownloadAddress() (*gjson.Result, error) {
	client, err := w.NewClient(w.Config, "dds")
	if err != nil {
		return nil, err
	}

	uri := "/v3/{project_id}/instances/{instance_id}/ssl-cert/download-link"
	uri = strings.ReplaceAll(uri, "{instance_id}", w.Get("instance_id").(string))
	return httphelper.New(client).
		Method("GET").
		URI(uri).
		Request().
		Result()
}

func (w *SslCertDownloadLinksDSWrapper) listSslCertDownloadAddressToSchema(body *gjson.Result) error {
	d := w.ResourceData
	mErr := multierror.Append(nil,
		d.Set("region", w.Config.GetRegion(w.ResourceData)),
		d.Set("certs", schemas.SliceToList(body.Get("certs"),
			func(certs gjson.Result) any {
				return map[string]any{
					"download_link": certs.Get("download_link").Value(),
					"category":      certs.Get("category").Value(),
				}
			},
		)),
	)
	return mErr.ErrorOrNil()
}
