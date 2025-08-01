---
subcategory: "Cloud Container Engine (CCE)"
layout: "huaweicloud"
page_title: "HuaweiCloud: huaweicloud_cce_node_pool"
description: ""
---

# huaweicloud_cce_node_pool

Add a node pool to a container cluster.

## Example Usage

### Basic Usage

```hcl
variable "cluster_id" {}
variable "key_pair" {}
variable "availability_zone" {}

resource "huaweicloud_cce_node_pool" "node_pool" {
  cluster_id               = var.cluster_id
  name                     = "testpool"
  os                       = "EulerOS 2.5"
  initial_node_count       = 2
  flavor_id                = "s3.large.4"
  availability_zone        = var.availability_zone
  key_pair                 = var.keypair
  scall_enable             = true
  min_node_count           = 1
  max_node_count           = 10
  scale_down_cooldown_time = 100
  priority                 = 1
  type                     = "vm"

  root_volume {
    size       = 40
    volumetype = "SAS"
  }
  data_volumes {
    size       = 100
    volumetype = "SAS"
  }
}
```

## Node pool with storage configuration

```hcl
variable "cluster_id"
variable "kms_key_id"
variable "key_pair" {}
variable "availability_zone" {}

resource "huaweicloud_cce_node_pool" "test" {
  cluster_id               = var.cluster_id
  name                     = "testpool"
  os                       = "EulerOS 2.5"
  flavor_id                = "s6.large.2"
  initial_node_count       = 1
  availability_zone        = var.availability_zone
  key_pair                 = var.key_pair
  scall_enable             = false
  min_node_count           = 0
  max_node_count           = 0
  scale_down_cooldown_time = 0
  priority                 = 0
  type                     = "vm"

  root_volume {
    size       = 40
    volumetype = "SSD"
  }
  
  data_volumes {
    size       = 100
    volumetype = "SSD"
    kms_key_id = var.kms_key_id
  }

  data_volumes {
    size       = 100
    volumetype = "SSD"
    kms_key_id = var.kms_key_id
  }

  storage {
    selectors {
      name              = "cceUse"
      type              = "evs"
      match_label_size  = "100"
      match_label_count = "1"
    }

    selectors {
      name                           = "user"
      type                           = "evs"
      match_label_size               = "100"
      match_label_metadata_encrypted = "1"
      match_label_metadata_cmkid     = var.kms_key_id
      match_label_count              = "1"
    }

    groups {
      name           = "vgpaas"
      selector_names = ["cceUse"]
      cce_managed    = true

      virtual_spaces {
        name        = "kubernetes"
        size        = "10%"
        lvm_lv_type = "linear"
      }

      virtual_spaces {
        name        = "runtime"
        size        = "90%"
      }
    }

    groups {
      name           = "vguser"
      selector_names = ["user"]

      virtual_spaces {
        name        = "user"
        size        = "100%"
        lvm_lv_type = "linear"
        lvm_path    = "/workspace"
      }
    }
  }
}
```

### PrePaid node pool

```hcl
variable "cluster_id" {}
variable "key_pair" {}
variable "availability_zone" {}

resource "huaweicloud_cce_node_pool" "node_pool" {
  cluster_id               = var.cluster_id
  name                     = "testpool"
  os                       = "EulerOS 2.5"
  initial_node_count       = 2
  flavor_id                = "s3.large.4"
  availability_zone        = var.availability_zone
  key_pair                 = var.keypair
  scall_enable             = true
  min_node_count           = 1
  max_node_count           = 10
  scale_down_cooldown_time = 100
  priority                 = 1
  type                     = "vm"
  charging_mode            = "prePaid"
  period_unit              = "month"
  period                   = 1

  root_volume {
    size       = 40
    volumetype = "SAS"
  }
  data_volumes {
    size       = 100
    volumetype = "SAS"
  }
}
```

  ~> You need to remove all nodes in the node pool on the console, before deleting a prepaid node pool.

## Node pool with extension scale groups

```hcl
variable "cluster_id" {}
variable "key_pair" {}
variable "availability_zone_1" {}
variable "availability_zone_2" {}

resource "huaweicloud_cce_node_pool" "node_pool" {
  cluster_id               = var.cluster_id
  name                     = "testpool"
  os                       = "EulerOS 2.5"
  initial_node_count       = 2
  flavor_id                = "s3.large.4"
  availability_zone        = var.availability_zone_1
  key_pair                 = var.keypair
  scall_enable             = true
  min_node_count           = 1
  max_node_count           = 10
  scale_down_cooldown_time = 100
  priority                 = 1
  type                     = "vm"

  root_volume {
    size       = 40
    volumetype = "SAS"
  }
  data_volumes {
    size       = 100
    volumetype = "SAS"
  }

  extension_scale_groups {
    metadata {
      name = "group1"
    }

    spec {
      flavor = "s3.large.4"
      az     = var.availability_zone_1

      autoscaling {
        extension_priority = 1
        enable             = true
      }
    }
  }

  extension_scale_groups {
    metadata {
      name = "group2"
    }

    spec {
      flavor = "s3.xlarge.4"
      az     = var.availability_zone_1

      autoscaling {
        extension_priority = 1
        enable             = true
      }
    }
  }

  extension_scale_groups {
    metadata {
      name = "group3"
    }

    spec {
      flavor = "s3.xlarge.4"
      az     = var.availability_zone_2

      autoscaling {
        extension_priority = 1
        enable             = true
      }
    }
  }
}
```

## Argument Reference

The following arguments are supported:

* `region` - (Optional, String, ForceNew) The region in which to create the CCE pool resource. If omitted, the
  provider-level region will be used. Changing this creates a new CCE node pool resource.

* `cluster_id` - (Required, String, NonUpdatable) Specifies the cluster ID.

* `name` - (Required, String) Specifies the node pool name.

* `initial_node_count` - (Required, Int) Specifies the initial number of expected nodes in the node pool.
  This parameter can be also used to manually scale the node count afterwards.

* `flavor_id` - (Required, String, NonUpdatable) Specifies the flavor ID.

* `type` - (Optional, String, NonUpdatable) Specifies the node pool type. Possible values are: **vm** and **ElasticBMS**.

* `availability_zone` - (Optional, String, NonUpdatable) Specifies the name of the available partition (AZ). Default value
  is random to create nodes in a random AZ in the node pool.

* `os` - (Optional, String) Specifies the operating system of the node.
  The value can be **EulerOS 2.9** and **CentOS 7.6** e.g. For more details,
  please see [documentation](https://support.huaweicloud.com/intl/en-us/api-cce/node-os.html).
  This parameter is required when the `node_image_id` in `extend_params` is not specified.

* `key_pair` - (Optional, String, NonUpdatable) Specifies the key pair name when logging in to select the key pair mode.
  This parameter and `password` are alternative.

* `password` - (Optional, String, NonUpdatable) Specifies the root password when logging in to select the password mode.
  The password consists of 8 to 26 characters and must contain at least three of following: uppercase letters,
  lowercase letters, digits, special characters(!@$%^-_=+[{}]:,./?~#*).
  This parameter can be plain or salted and is alternative to `key_pair`.

* `subnet_id` - (Optional, String) Specifies the ID of the subnet to which the NIC belongs.

* `subnet_list` - (Optional, List) Specifies the ID list of the subnet to which the NIC belongs.

* `ecs_group_id` - (Optional, String, NonUpdatable) Specifies the ECS group ID. If specified, the node will be created under
  the cloud server group.

* `extend_params` - (Optional, List, NonUpdatable) Specifies the extended parameters.
  The [object](#extend_params) structure is documented below.

* `scall_enable` - (Optional, Bool) Specifies whether to enable auto scaling.
  If Autoscaler is enabled, install the autoscaler add-on to use the auto scaling feature.

* `min_node_count` - (Optional, Int) Specifies the minimum number of nodes allowed if auto scaling is enabled.

* `max_node_count` - (Optional, Int) Specifies the maximum number of nodes allowed if auto scaling is enabled.

* `scale_down_cooldown_time` - (Optional, Int) Specifies the time interval between two scaling operations, in minutes.

* `priority` - (Optional, Int) Specifies the weight of the node pool.
  A node pool with a higher weight has a higher priority during scaling.

* `security_groups` - (Optional, List, NonUpdatable) Specifies the list of custom security group IDs for the node pool.
  If specified, the nodes will be put in these security groups. When specifying a security group, do not modify
  the rules of the port on which CCE running depends. For details, see
  [documentation](https://support.huaweicloud.com/intl/en-us/cce_faq/cce_faq_00265.html).

* `pod_security_groups` - (Optional, List, NonUpdatable) Specifies the list of security group IDs for the pod.
  Only supported in CCE Turbo clusters of v1.19 and above.

* `initialized_conditions` - (Optional, List) Specifies the custom initialization flags.

* `labels` - (Optional, Map) Specifies the tags of a Kubernetes node, key/value pair format.

* `tags` - (Optional, Map) Specifies the tags of a VM node, key/value pair format.

* `root_volume` - (Required, List, NonUpdatable) Specifies the configuration of the system disk.
  The structure is described below.

* `data_volumes` - (Required, List, NonUpdatable) Specifies the configuration of the data disks.
  The structure is described below.

* `charging_mode` - (Optional, String, NonUpdatable) Specifies the charging mode of the CCE node pool. Valid values are
  *prePaid* and *postPaid*, defaults to *postPaid*.

* `period_unit` - (Optional, String, NonUpdatable) Specifies the charging period unit of the CCE node pool.
  Valid values are *month* and *year*. This parameter is mandatory if `charging_mode` is set to *prePaid*.

* `period` - (Optional, Int, NonUpdatable) Specifies the charging period of the CCE node pool. If `period_unit` is set to
  *month*, the value ranges from 1 to 9. If `period_unit` is set to *year*, the value ranges from 1 to 3. This parameter
  is mandatory if `charging_mode` is set to *prePaid*.

* `auto_renew` - (Optional, String, NonUpdatable) Specifies whether auto renew is enabled. Valid values are "true" and "false".

* `runtime` - (Optional, String, NonUpdatable) Specifies the runtime of the CCE node pool. Valid values are *docker* and
  *containerd*.

* `taints` - (Optional, List) Specifies the taints configuration of the nodes to set anti-affinity.
  The structure is described below.

* `tag_policy_on_existing_nodes` - (Optional, String) Specifies the tag policy on existing nodes.
  The value can be **ignore** and **refresh**, defaults to **ignore**.

* `label_policy_on_existing_nodes` - (Optional, String) Specifies the label policy on existing nodes.
  The value can be **ignore** and **refresh**, defaults to **refresh**.

* `taint_policy_on_existing_nodes` - (Optional, String) Specifies the taint policy on existing nodes.
  The value can be **ignore** and **refresh**, defaults to **refresh**.

* `enterprise_project_id` - (Optional, String) Specifies the enterprise project ID of the node pool.
  If updated, the new value will apply only to new nodes.

* `hostname_config` - (Optional, List, NonUpdatable) Specifies the hostname config of the kubernetes node,
  which is supported by clusters of v1.23.6-r0 to v1.25 or clusters of v1.25.2-r0 or later versions.
  The [object](#hostname_config) structure is documented below.

* `partition` - (Optional, String, NonUpdatable) Specifies the partition to which the node belongs. Value options:
  + **center**: center cloud.
  + The availability zone ID of the edge station.

* `extension_scale_groups` - (Optional, List) Specifies the configurations of extended scaling groups in the node pool.
  The [object](#extension_scale_groups) structure is documented below.

* `storage` - (Optional, List, NonUpdatable) Specifies the disk initialization management parameter.
  If omitted, disks are managed based on the DockerLVMConfigOverride parameter in extendParam.
  This parameter is supported for clusters of v1.15.11 and later.
  If the node has both local and EVS disks attached,
  this parameter must be specified, or it may result in unexpected disk partitions.
  If you want to change the value range of a data disk to **20** to **32768**, this parameter must be specified.
  If you want to use the shared disk space (with the runtime and Kubernetes partitions cancelled),
  this parameter must be specified.
  If you want to store system components in the system disk, this parameter must be specified.

  + `selectors` - (Required, List, NonUpdatable) Specifies the disk selection.
    Matched disks are managed according to match labels and storage type. Structure is documented below.

  + `groups` - (Required, List, NonUpdatable) Specifies the storage group consists of multiple storage devices.
    This is used to divide storage space. Structure is documented below.

The `root_volume` block supports:

* `size` - (Required, Int, NonUpdatable) Specifies the disk size in GB.

* `volumetype` - (Required, String, NonUpdatable) Specifies the disk type.

* `extend_params` - (Optional, Map, NonUpdatable) Specifies the disk expansion parameters.

* `kms_key_id` - (Optional, String, NonUpdatable) Specifies the KMS key ID. This is used to encrypt the volume.

* `dss_pool_id` - (Optional, String, NonUpdatable) Specifies the DSS pool ID. This field is used only for dedicated storage.

* `iops` - (Optional, Int, NonUpdatable) Specifies the iops of the disk,
  required when `volumetype` is **GPSSD2** or **ESSD2**.
  
* `throughput` - (Optional, Int, NonUpdatable) Specifies the throughput of the disk in MiB/s,
  required when `volumetype` is **GPSSD2**.

The `data_volumes` block supports:

* `size` - (Required, Int, NonUpdatable) Specifies the disk size in GB.

* `volumetype` - (Required, String, NonUpdatable) Specifies the disk type.

* `extend_params` - (Optional, Map, NonUpdatable) Specifies the disk expansion parameters.

* `kms_key_id` - (Optional, String, NonUpdatable) Specifies the KMS key ID. This is used to encrypt the volume.

* `dss_pool_id` - (Optional, String, NonUpdatable) Specifies the DSS pool ID. This field is used only for dedicated storage.

* `iops` - (Optional, Int, NonUpdatable) Specifies the iops of the disk,
  required when `volumetype` is **GPSSD2** or **ESSD2**.
  
* `throughput` - (Optional, Int, NonUpdatable) Specifies the throughput of the disk in MiB/s,
  required when `volumetype` is **GPSSD2**.

  -> You need to create an agency (EVSAccessKMS) when disk encryption is used in the current project for the first time ever.

The `taints` block supports:

* `key` - (Required, String) A key must contain 1 to 63 characters starting with a letter or digit. Only letters,
  digits, hyphens (-), underscores (_), and periods (.) are allowed. A DNS subdomain name can be used as the
  prefix of a key.

* `value` - (Required, String) A value must start with a letter or digit and can contain a maximum of 63 characters,
  including letters, digits, hyphens (-), underscores (_), and periods (.).

* `effect` - (Required, String) Available options are NoSchedule, PreferNoSchedule, and NoExecute.

<a name="extend_params"></a>
The `extend_params` block supports:

* `max_pods` - (Optional, Int, NonUpdatable) Specifies the maximum number of instances a node is allowed to create.

* `docker_base_size` - (Optional, Int, NonUpdatable) Specifies the available disk space of a single container on a node,
  in GB.

* `preinstall` - (Optional, String, NonUpdatable) Specifies the script to be executed before installation.
  The input value can be a Base64 encoded string or not.

* `postinstall` - (Optional, String, NonUpdatable) Specifies the script to be executed after installation.
  The input value can be a Base64 encoded string or not.

* `node_image_id` - (Optional, String, NonUpdatable) Specifies the image ID to create the node.

* `node_multi_queue` - (Optional, String, NonUpdatable) Specifies the number of ENI queues.
  Example setting: **"[{\"queue\":4}]"**.

* `nic_threshold` - (Optional, String, NonUpdatable) Specifies the ENI pre-binding thresholds.
  Example setting: **"0.3:0.6"**.

* `agency_name` - (Optional, String, NonUpdatable) Specifies the agency name.

* `kube_reserved_mem` - (Optional, Int, NonUpdatable) Specifies the reserved node memory, which is reserved for
  Kubernetes-related components.

* `system_reserved_mem` - (Optional, Int, NonUpdatable) Specifies the reserved node memory, which is reserved
  value for system components.

* `security_reinforcement_type` - (Optional, String, NonUpdatable) Specifies the security reinforcement type.
  The value can be: **null** or **cybersecurity**.

The `selectors` block supports:

* `name` - (Required, String, NonUpdatable) Specifies the selector name, used as the index of `selector_names`
  in storage group. The name of each selector must be unique.

* `type` - (Optional, String, NonUpdatable) Specifies the storage type. Currently, only **evs (EVS volumes)** is supported.
  The default value is **evs**.

* `match_label_size` - (Optional, String, NonUpdatable) Specifies the matched disk size. If omitted,
  the disk size is not limited. Example: 100.

* `match_label_volume_type` - (Optional, String, NonUpdatable) Specifies the EVS disk type. Currently,
  **SSD**, **GPSSD**, and **SAS** are supported. If omitted, the disk type is not limited.

* `match_label_metadata_encrypted` - (Optional, String, NonUpdatable) Specifies the disk encryption identifier.
  Values can be: **0** indicates that the disk is not encrypted and **1** indicates that the disk is encrypted.
  If omitted, whether the disk is encrypted is not limited.

* `match_label_metadata_cmkid` - (Optional, String, NonUpdatable) Specifies the customer master key ID of an encrypted
  disk.

* `match_label_count` - (Optional, String, NonUpdatable) Specifies the number of disks to be selected. If omitted,
  all disks of this type are selected.

The `groups` block supports:

* `name` - (Required, String, NonUpdatable) Specifies the name of a virtual storage group. Each group name must be unique.

* `cce_managed` - (Optional, Bool, NonUpdatable) Specifies the whether the storage space is for **kubernetes** and
  **runtime** components. Only one group can be set to true. The default value is **false**.

* `selector_names` - (Required, List, NonUpdatable) Specifies the list of names of selectors to match.
  This parameter corresponds to name in `selectors`. A group can match multiple selectors,
  but a selector can match only one group.

* `virtual_spaces` - (Required, List, NonUpdatable) Specifies the detailed management of space configuration in a group.

  + `name` - (Required, String, NonUpdatable) Specifies the virtual space name. Currently, only **kubernetes**, **runtime**,
    and **user** are supported.

  + `size` - (Required, String, NonUpdatable) Specifies the size of a virtual space. Only an integer percentage is supported.
    Example: 90%. Note that the total percentage of all virtual spaces in a group cannot exceed 100%.

  + `lvm_lv_type` - (Optional, String, NonUpdatable) Specifies the LVM write mode, values can be **linear** and **striped**.
    This parameter takes effect only in **kubernetes** and **user** configuration.

  + `lvm_path` - (Optional, String, NonUpdatable) Specifies the absolute path to which the disk is attached.
    This parameter takes effect only in **user** configuration.

  + `runtime_lv_type` - (Optional, String, NonUpdatable) Specifies the LVM write mode, values can be **linear** and **striped**.
    This parameter takes effect only in **runtime** configuration.

<a name="hostname_config"></a>
The `hostname_config` block supports:

* `type` - (Required, String, NonUpdatable) Specifies the hostname type of the kubernetes node.
  The value can be:
  + **privateIp**: The Kubernetes node is named after its IP address.
  + **cceNodeName**: The Kubernetes node is named after the CCE node.
  
  If `hostname_config` not specified, the default value is **privateIp**.

  ~>For a node which is configured using cceNodeName, the name is the same as the Kubernetes node name and the ECS name.
    The node name cannot be changed. If the ECS name is changed on the ECS console, the node name will retain unchanged
    after ECS synchronization. To avoid a conflict between Kubernetes nodes, the system automatically adds a suffix to
    each node name. The suffix is in the format of A hyphen (-) Five random characters. The value of the random
    characters is a lowercase letter or a digit ranging from 0 to 9.

<a name="extension_scale_groups"></a>
The `extension_scale_groups` block supports:

* `metadata` - (Optional, List) Specifies the basic information about the extended scaling group.
  The [object](#metadata) structure is documented below.

* `spec` - (Optional, List) Specifies the configurations of the extended scaling group,
  which carry different configurations from those of the default scaling group.
  The [object](#spec) structure is documented below.

<a name="metadata"></a>
The `metadata` block supports:

* `name` - (Optional, String) Specifies the name of an extended scaling group.
  The value cannot be default and can contain a maximum of 55 characters.
  Only digits, lowercase letters, and hyphens (-) are allowed.

<a name="spec"></a>
The `spec` block supports:

* `flavor` - (Optional, String) Specifies the node flavor.

* `az` - (Optional, String) Specifies the availability zone of a node.
  If this parameter is not specified or left blank, the default scaling group configurations take effect.

* `capacity_reservation_specification` - (Optional, List) Specifies the capacity reservation
  configurations of the extended scaling group.
  The [object](#capacity_reservation_specification) structure is documented below.

* `autoscaling` - (Optional, List) Specifies the auto scaling configurations of the extended scaling group.
  The [object](#autoscaling) structure is documented below.

<a name="capacity_reservation_specification"></a>
The `capacity_reservation_specification` block supports:

* `id` - (Optional, String) Specifies the private pool ID.
  The parameter value can be ignored when preference is set to none.

* `preference` - (Optional, String) Specifies the capacity of a private storage pool. If the value is none,
  the capacity reservation is not specified. If the value is targeted, the capacity reservation is specified.
  In this case, the `id` cannot be left blank.

<a name="autoscaling"></a>
The `autoscaling` block supports:

* `enable` - (Optional, Bool) Specifies whether to enable auto scaling for the scaling group, defaults to **false**.

* `extension_priority` - (Optional, Int) Specifies the priority of the scaling group, defaults to **0**.
  A higher value indicates a greater priority.

* `min_node_count` - (Optional, Int) Specifies the minimum number of nodes in the scaling group during auto scaling.
  The value must be greater than **0**.

* `max_node_count` - (Optional, Int) Specifies the maximum number of nodes that can be retained in the scaling group
  during auto scaling. The value must be greater than or equal to that of `min_node_count`, and can neither be greater
  than the maximum number of nodes allowed by the cluster nor the maximum number of nodes in the node pool.

## Attribute Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The resource ID in UUID format.

* `status` - Node status information.

* `billing_mode` - Billing mode of a node.

* `current_node_count` - The current number of the nodes.

* `extension_scale_groups` - The configurations of extended scaling groups in the node pool.
  The [object](#extension_scale_groups--attribute) structure is documented below.

<a name="extension_scale_groups--attribute"></a>
The `extension_scale_groups` block supports:

* `metadata` - The basic information about the extended scaling group.
  The [object](#metadata--attribute) structure is documented below.

<a name="metadata--attribute"></a>
The `metadata` block supports:

* `uid` - The ID of the extended scaling group.

## Timeouts

This resource provides the following timeouts configuration options:

* `create` - Default is 20 minutes.
* `delete` - Default is 20 minutes.

## Import

CCE node pool can be imported using the cluster ID and node pool ID separated by a slash, e.g.

```bash
$ terraform import huaweicloud_cce_node_pool.my_node_pool <cluster_id>/<id>
```

Note that the imported state may not be identical to your resource definition, due to some attributes missing from the
API response, security or some other reason. The missing attributes include:
`password`, `extend_params`, `taints`, `initial_node_count` and `pod_security_groups`.
It is generally recommended running `terraform plan` after importing a node pool.
You can then decide if changes should be applied to the node pool, or the resource
definition should be updated to align with the node pool. Also you can ignore changes as below.

```hcl
resource "huaweicloud_cce_node_pool" "my_node_pool" {
  ...

  lifecycle {
    ignore_changes = [
      password, extend_params,
    ]
  }
}
```
