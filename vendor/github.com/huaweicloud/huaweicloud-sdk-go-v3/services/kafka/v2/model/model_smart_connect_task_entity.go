package model

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"

	"strings"
)

type SmartConnectTaskEntity struct {

	// SmartConnect任务名称。
	TaskName *string `json:"task_name,omitempty"`

	// SmartConnect任务配置的Topic。
	Topics *string `json:"topics,omitempty"`

	// SmartConnect任务的源端类型。
	SourceType *string `json:"source_type,omitempty"`

	SourceTask *SmartConnectTaskRespSourceConfig `json:"source_task,omitempty"`

	// SmartConnect任务的目标端类型。
	SinkType *string `json:"sink_type,omitempty"`

	SinkTask *SmartConnectTaskRespSinkConfig `json:"sink_task,omitempty"`

	// SmartConnect任务的id。
	Id *string `json:"id,omitempty"`

	// SmartConnect任务的状态。
	Status *string `json:"status,omitempty"`

	// SmartConnect任务的创建时间。
	CreateTime *int64 `json:"create_time,omitempty"`
}

func (o SmartConnectTaskEntity) String() string {
	data, err := utils.Marshal(o)
	if err != nil {
		return "SmartConnectTaskEntity struct{}"
	}

	return strings.Join([]string{"SmartConnectTaskEntity", string(data)}, " ")
}