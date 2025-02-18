// Generated by PMS #180
package rms

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
	"github.com/huaweicloud/terraform-provider-huaweicloud/huaweicloud/utils"
)

func DataSourceRmsAggregationPendingRequests() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceRmsAggregationPendingRequestsRead,

		Schema: map[string]*schema.Schema{
			"account_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `Specifies the ID of the authorized resource aggregator account.`,
			},
			"pending_aggregation_requests": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: `The list of pending aggregation requests.`,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"requester_account_id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: `The ID of the account that requests aggregated data.`,
						},
					},
				},
			},
		},
	}
}

type AggregationPendingRequestsDSWrapper struct {
	*schemas.ResourceDataWrapper
	Config *config.Config
}

func newAggregationPendingRequestsDSWrapper(d *schema.ResourceData, meta interface{}) *AggregationPendingRequestsDSWrapper {
	return &AggregationPendingRequestsDSWrapper{
		ResourceDataWrapper: schemas.NewSchemaWrapper(d),
		Config:              meta.(*config.Config),
	}
}

func dataSourceRmsAggregationPendingRequestsRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	wrapper := newAggregationPendingRequestsDSWrapper(d, meta)
	lisPenAggReqRst, err := wrapper.ListPendingAggregationRequests()
	if err != nil {
		return diag.FromErr(err)
	}

	id, err := uuid.GenerateUUID()
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(id)

	err = wrapper.listPendingAggregationRequestsToSchema(lisPenAggReqRst)
	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}

// @API CONFIG GET /v1/resource-manager/domains/{domain_id}/aggregators/pending-aggregation-request
func (w *AggregationPendingRequestsDSWrapper) ListPendingAggregationRequests() (*gjson.Result, error) {
	client, err := w.NewClient(w.Config, "rms")
	if err != nil {
		return nil, err
	}

	uri := "/v1/resource-manager/domains/{domain_id}/aggregators/pending-aggregation-request"
	uri = strings.ReplaceAll(uri, "{domain_id}", w.Config.DomainID)
	params := map[string]any{
		"account_id": w.Get("account_id"),
	}
	params = utils.RemoveNil(params)
	return httphelper.New(client).
		Method("GET").
		URI(uri).
		Query(params).
		MarkerPager("pending_aggregation_requests", "page_info.next_marker", "marker").
		OkCode(200).
		Request().
		Result()
}

func (w *AggregationPendingRequestsDSWrapper) listPendingAggregationRequestsToSchema(body *gjson.Result) error {
	d := w.ResourceData
	mErr := multierror.Append(nil,
		d.Set("pending_aggregation_requests", schemas.SliceToList(body.Get("pending_aggregation_requests"),
			func(penAggRequests gjson.Result) any {
				return map[string]any{
					"requester_account_id": penAggRequests.Get("requester_account_id").Value(),
				}
			},
		)),
	)
	return mErr.ErrorOrNil()
}
