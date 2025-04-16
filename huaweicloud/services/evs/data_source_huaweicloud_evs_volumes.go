package evs

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/chnsz/golangsdk"

	"github.com/huaweicloud/terraform-provider-huaweicloud/huaweicloud/config"
	"github.com/huaweicloud/terraform-provider-huaweicloud/huaweicloud/utils"
)

// @API EVS GET /v2/{project_id}/cloudvolumes/detail
func DataSourceEvsVolumes() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceEvsVolumesRead,

		Schema: map[string]*schema.Schema{
			"region": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"volume_id": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"name": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"volume_type_id": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"availability_zone": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"enterprise_project_id": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"shareable": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"server_id": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"status": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"tags": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"volumes": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"attachments": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"id": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"attached_at": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"attached_mode": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"device_name": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"server_id": {
										Type:     schema.TypeString,
										Computed: true,
									},
								},
							},
						},
						"availability_zone": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"bootable": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"description": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"volume_type": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"iops": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"throughput": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"enterprise_project_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"service_type": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"shareable": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"size": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"status": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"create_at": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"update_at": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"tags": {
							Type:     schema.TypeMap,
							Computed: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"wwn": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func buildEvsVolumesQueryParams(d *schema.ResourceData, cfg *config.Config) string {
	rst := ""
	if v, ok := d.GetOk("volume_id"); ok {
		rst += fmt.Sprintf("&id=%v", v)
	}
	if v, ok := d.GetOk("name"); ok {
		rst += fmt.Sprintf("&name=%v", v)
	}
	if v, ok := d.GetOk("volume_type_id"); ok {
		rst += fmt.Sprintf("&volume_type_id=%v", v)
	}
	if v, ok := d.GetOk("availability_zone"); ok {
		rst += fmt.Sprintf("&availability_zone=%v", v)
	}
	if v := cfg.GetEnterpriseProjectID(d, "all_granted_eps"); v != "" {
		rst += fmt.Sprintf("&enterprise_project_id=%v", v)
	}
	if v, ok := d.GetOk("server_id"); ok {
		rst += fmt.Sprintf("&server_id=%v", v)
	}
	if v, ok := d.GetOk("status"); ok {
		rst += fmt.Sprintf("&status=%v", v)
	}
	if v, ok := d.GetOk("shareable"); ok {
		rst += fmt.Sprintf("&multiattach=%v", v)
	}

	if rst != "" {
		rst = "?" + rst[1:]
	}
	return rst
}

func buildRequestPathWithOffset(queryParams string, offset int) string {
	if offset == 0 {
		// Ignore the offset of the first page
		return queryParams
	}

	if queryParams == "" {
		// No query conditions were added
		return fmt.Sprintf("?offset=%d", offset)
	}

	return fmt.Sprintf("%s&offset=%d", queryParams, offset)
}

func dataSourceEvsVolumesRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var (
		cfg         = meta.(*config.Config)
		region      = cfg.GetRegion(d)
		httpUrl     = "v2/{project_id}/cloudvolumes/detail"
		product     = "evs"
		queryParams = buildEvsVolumesQueryParams(d, cfg)
		offset      = 0
		allVolumes  []interface{}
	)
	client, err := cfg.NewServiceClient(product, region)
	if err != nil {
		return diag.Errorf("error creating EVS client: %s", err)
	}

	requestPath := client.Endpoint + httpUrl
	requestPath = strings.ReplaceAll(requestPath, "{project_id}", client.ProjectID)
	requestOpt := golangsdk.RequestOpts{
		KeepResponseBody: true,
	}

	for {
		requestPathWithOffset := requestPath + buildRequestPathWithOffset(queryParams, offset)
		resp, err := client.Request("GET", requestPathWithOffset, &requestOpt)
		if err != nil {
			return diag.Errorf("error retrieving EVS volumes: %s", err)
		}

		respBody, err := utils.FlattenResponse(resp)
		if err != nil {
			return diag.FromErr(err)
		}

		volumes := utils.PathSearch("volumes", respBody, make([]interface{}, 0)).([]interface{})
		if len(volumes) == 0 {
			break
		}

		allVolumes = append(allVolumes, volumes...)
		offset += len(volumes)
	}

	generateUUID, err := uuid.GenerateUUID()
	if err != nil {
		return diag.Errorf("unable to generate ID: %s", err)
	}

	d.SetId(generateUUID)
	mErr := multierror.Append(
		d.Set("region", region),
		d.Set("volumes", flattenEvsVolumes(filterEvsVolumes(allVolumes, d))),
	)

	return diag.FromErr(mErr.ErrorOrNil())
}

func flattenEvsVolumes(allVolumes []interface{}) []interface{} {
	rst := make([]interface{}, 0, len(allVolumes))
	for _, v := range allVolumes {
		rst = append(rst, map[string]interface{}{
			"id":                    utils.PathSearch("id", v, nil),
			"attachments":           flattenAttachments(v),
			"availability_zone":     utils.PathSearch("availability_zone", v, nil),
			"description":           utils.PathSearch("description", v, nil),
			"volume_type":           utils.PathSearch("volume_type", v, nil),
			"iops":                  utils.PathSearch("iops.total_val", v, nil),
			"throughput":            utils.PathSearch("throughput.total_val", v, nil),
			"enterprise_project_id": utils.PathSearch("enterprise_project_id", v, nil),
			"name":                  utils.PathSearch("name", v, nil),
			"service_type":          utils.PathSearch("service_type", v, nil),
			"shareable":             utils.PathSearch("multiattach", v, nil),
			"size":                  utils.PathSearch("size", v, nil),
			"status":                utils.PathSearch("status", v, nil),
			"create_at":             utils.PathSearch("created_at", v, nil),
			"update_at":             utils.PathSearch("updated_at", v, nil),
			"tags":                  utils.PathSearch("tags", v, nil),
			"wwn":                   utils.PathSearch("wwn", v, nil),
			"bootable":              flattenBootable(v),
		})
	}

	return rst
}

func flattenBootable(respBody interface{}) bool {
	bootableString := utils.PathSearch("bootable", respBody, "").(string)
	bootable, err := strconv.ParseBool(bootableString)
	if err != nil {
		log.Printf("[ERROR] the bootable of volume (%s) connot be converted from boolen to string: %s",
			utils.PathSearch("id", respBody, "").(string),
			err)
	}

	return bootable
}

func flattenAttachments(respBody interface{}) []interface{} {
	attachments := utils.PathSearch("attachments", respBody, make([]interface{}, 0)).([]interface{})
	attachedMode := utils.PathSearch("metadata.attached_mode", respBody, "").(string)
	rst := make([]interface{}, 0, len(attachments))
	for _, v := range attachments {
		rst = append(rst, map[string]interface{}{
			"id":            utils.PathSearch("attachment_id", v, nil),
			"attached_at":   utils.PathSearch("attached_at", v, nil),
			"attached_mode": attachedMode,
			"device_name":   utils.PathSearch("device", v, nil),
			"server_id":     utils.PathSearch("server_id", v, nil),
		})
	}

	return rst
}

func filterEvsVolumes(allVolumes []interface{}, d *schema.ResourceData) []interface{} {
	localTags := d.Get("tags").(map[string]interface{})
	if len(localTags) == 0 {
		return allVolumes
	}

	rst := make([]interface{}, 0, len(allVolumes))
	for _, v := range allVolumes {
		remoteTags := utils.PathSearch("tags", v, make(map[string]string)).(map[string]string)
		if utils.HasMapContains(remoteTags, localTags) {
			rst = append(rst, v)
		}
	}

	return rst
}
