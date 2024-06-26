// Generated by PMS #190
package apig

import (
	"context"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/tidwall/gjson"

	"github.com/huaweicloud/terraform-provider-huaweicloud/huaweicloud/config"
	"github.com/huaweicloud/terraform-provider-huaweicloud/huaweicloud/helper/filters"
	"github.com/huaweicloud/terraform-provider-huaweicloud/huaweicloud/helper/httphelper"
	"github.com/huaweicloud/terraform-provider-huaweicloud/huaweicloud/helper/schemas"
	"github.com/huaweicloud/terraform-provider-huaweicloud/huaweicloud/utils"
)

func DataSourceApigApplicationQuotas() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceApigApplicationQuotasRead,

		Schema: map[string]*schema.Schema{
			"region": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: `The region in which to query the resource.`,
			},
			"instance_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: `The ID of the dedicated instance to which the application quotas belong.`,
			},
			"name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `The name of the application quota to be queried.`,
			},
			"quota_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `The ID of the application quota.`,
			},
			"quotas": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: `All application quotas that match the filter parameters.`,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: `The ID of the application quota.`,
						},
						"name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: `The name of the application quota.`,
						},
						"description": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: `The description of the application quota.`,
						},
						"call_limits": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: `The maximum number of times a application quota can be called.`,
						},
						"time_unit": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: `The time unit.`,
						},
						"time_interval": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: `The time limit of a quota.`,
						},
						"bound_app_num": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: `The number of applications bound to the quota policy.`,
						},
						"created_at": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: `The creation time of the application quota, in RFC3339 format.`,
						},
					},
				},
			},
		},
	}
}

type ApplicationQuotasDSWrapper struct {
	*schemas.ResourceDataWrapper
	Config *config.Config
}

func newApplicationQuotasDSWrapper(d *schema.ResourceData, meta interface{}) *ApplicationQuotasDSWrapper {
	return &ApplicationQuotasDSWrapper{
		ResourceDataWrapper: schemas.NewSchemaWrapper(d),
		Config:              meta.(*config.Config),
	}
}

func dataSourceApigApplicationQuotasRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	wrapper := newApplicationQuotasDSWrapper(d, meta)
	lisAppQuoRst, err := wrapper.ListAppQuotas()
	if err != nil {
		return diag.FromErr(err)
	}

	id, err := uuid.GenerateUUID()
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(id)

	err = wrapper.listAppQuotasToSchema(lisAppQuoRst)
	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}

// @API APIG GET /v2/{project_id}/apigw/instances/{instance_id}/app-quotas
func (w *ApplicationQuotasDSWrapper) ListAppQuotas() (*gjson.Result, error) {
	client, err := w.NewClient(w.Config, "apig")
	if err != nil {
		return nil, err
	}

	uri := "/v2/{project_id}/apigw/instances/{instance_id}/app-quotas"
	uri = strings.ReplaceAll(uri, "{instance_id}", w.Get("instance_id").(string))
	params := map[string]any{
		"name": w.Get("name"),
	}
	params = utils.RemoveNil(params)
	return httphelper.New(client).
		Method("GET").
		URI(uri).
		Query(params).
		OffsetPager("quotas", "offset", "limit", 100).
		Filter(
			filters.New().From("quotas").
				Where("app_quota_id", "=", w.Get("quota_id")),
		).
		OkCode(200).
		Request().
		Result()
}

func (w *ApplicationQuotasDSWrapper) listAppQuotasToSchema(body *gjson.Result) error {
	d := w.ResourceData
	mErr := multierror.Append(nil,
		d.Set("region", w.Config.GetRegion(w.ResourceData)),
		d.Set("quotas", schemas.SliceToList(body.Get("quotas"),
			func(quotas gjson.Result) any {
				return map[string]any{
					"id":            quotas.Get("app_quota_id").Value(),
					"name":          quotas.Get("name").Value(),
					"description":   quotas.Get("remark").Value(),
					"call_limits":   quotas.Get("call_limits").Value(),
					"time_unit":     quotas.Get("time_unit").Value(),
					"time_interval": quotas.Get("time_interval").Value(),
					"bound_app_num": quotas.Get("bound_app_num").Value(),
					"created_at":    w.setQuoCreTim(quotas),
				}
			},
		)),
	)
	return mErr.ErrorOrNil()
}

func (*ApplicationQuotasDSWrapper) setQuoCreTim(data gjson.Result) string {
	return utils.FormatTimeStampRFC3339(utils.ConvertTimeStrToNanoTimestamp(data.Get("create_time").String())/1000, false)
}
