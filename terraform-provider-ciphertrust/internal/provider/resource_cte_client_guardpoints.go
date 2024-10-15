package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceCTEClientGP{}
	_ resource.ResourceWithConfigure = &resourceCTEClientGP{}
)

func NewResourceCTEClientGP() resource.Resource {
	return &resourceCTEClientGP{}
}

type resourceCTEClientGP struct {
	client *Client
}

func (r *resourceCTEClientGP) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_client_guardpoint"
}

// Schema defines the schema for the resource.
func (r *resourceCTEClientGP) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"client_id": schema.StringAttribute{
				Required:    true,
				Description: "CTE Client ID to be updated",
			},
			"gp_id": schema.StringAttribute{
				Optional:    true,
				Description: "CTE Client Guardpoint ID to be updated or deleted",
			},
			"guard_paths": schema.ListAttribute{
				Required:    true,
				ElementType: types.StringType,
				Description: "List of GuardPaths to be created.",
			},
			"data_classification_enabled": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether data classification (tagging) is enabled. Enabled by default if the aligned policy contains ClassificationTags. Supported for Standard and LDT policies.",
			},
			"data_lineage_enabled": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether data lineage (tracking) is enabled. Enabled only if data classification is enabled. Supported for Standard and LDT policies.",
			},
			"guard_enabled": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether the GuardPoint is enabled.",
			},
			"mfa_enabled": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether MFA is enabled",
			},
			"network_share_credentials_id": schema.StringAttribute{
				Required:    true,
				Description: "ID/Name of the credentials if the GuardPoint is applied to a network share. Supported for only LDT policies.",
			},
			"guard_point_params": schema.ListNestedAttribute{
				Required:    true,
				Description: "Parameters for creating a GuardPoint",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"guard_point_type": schema.StringAttribute{
							Required:    true,
							Description: "Type of the GuardPoint",
							Validators: []validator.String{
								stringvalidator.OneOf([]string{"directory_auto", "directory_manual", "rawdevice_manual", "rawdevice_auto", "cloudstorage_auto", "cloudstorage_manual", "ransomware_protection"}...),
							},
						},
						"policy_id": schema.StringAttribute{
							Required:    true,
							Description: "ID of the policy applied with this GuardPoint. This parameter is not valid for Ransomware GuardPoints as they will not be associated with any CTE policy.",
						},
						"automount_enabled": schema.BoolAttribute{
							Optional:    true,
							Description: "Whether automount is enabled with the GuardPoint. Supported for Standard and LDT policies.",
						},
						"cifs_enabled": schema.BoolAttribute{
							Optional:    true,
							Description: "Whether to enable CIFS. Available on LDT enabled windows clients only. The default value is false. If you enable the setting, it cannot be disabled. Supported for only LDT policies.",
						},
						"data_classification_enabled": schema.BoolAttribute{
							Optional:    true,
							Description: "Whether data classification (tagging) is enabled. Enabled by default if the aligned policy contains ClassificationTags. Supported for Standard and LDT policies.",
						},
						"data_lineage_enabled": schema.BoolAttribute{
							Optional:    true,
							Description: "Whether data lineage (tracking) is enabled. Enabled only if data classification is enabled. Supported for Standard and LDT policies.",
						},
						"disk_name": schema.StringAttribute{
							Required:    true,
							Description: "Name of the disk if the selected raw partition is a member of an Oracle ASM disk group.",
						},
						"diskgroup_name": schema.StringAttribute{
							Required:    true,
							Description: "Name of the disk group if the selected raw partition is a member of an Oracle ASM disk group.",
						},
						"early_access": schema.BoolAttribute{
							Optional:    true,
							Description: "Whether secure start (early access) is turned on. Secure start is applicable to Windows clients only. Supported for Standard and LDT policies. The default value is false.",
						},
						"intelligent_protection": schema.BoolAttribute{
							Optional:    true,
							Description: "Flag to enable intelligent protection for this GuardPoint. This flag is valid for GuardPoints with classification based policy only. Can only be set during GuardPoint creation.",
						},
						"is_idt_capable_device": schema.BoolAttribute{
							Optional:    true,
							Description: "Whether the device where GuardPoint is applied is IDT capable or not. Supported for IDT policies.",
						},
						"mfa_enabled": schema.BoolAttribute{
							Optional:    true,
							Description: "Whether MFA is enabled",
						},
						"network_share_credentials_id": schema.StringAttribute{
							Required:    true,
							Description: "ID/Name of the credentials if the GuardPoint is applied to a network share. Supported for only LDT policies.",
						},
						"preserve_sparse_regions": schema.BoolAttribute{
							Optional:    true,
							Description: "Whether to preserve sparse file regions. Available on LDT enabled clients only. The default value is true. If you disable the setting, it cannot be enabled again. Supported for only LDT policies.",
						},
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEClientGP) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, MSG_METHOD_START+"[resource_cte_client_guardpoints.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan tfsdkCTEClientGuardPoint
	var guardpointParamsPlan tfsdkCTEClientGuardPointParamsModel
	var payload CTEClientGuardPointJSON
	var guardpointParamsPayload CTEClientGuardPointParamsJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if (tfsdkCTEClientGuardPointParamsModel{} != plan.GuardPointParams) {
		if guardpointParamsPlan.GPType.ValueString() != "" && guardpointParamsPlan.GPType.ValueString() != types.StringNull().ValueString() {
			guardpointParamsPayload.GPType = string(guardpointParamsPlan.GPType.ValueString())
		}
		if guardpointParamsPlan.PolicyID.ValueString() != "" && guardpointParamsPlan.PolicyID.ValueString() != types.StringNull().ValueString() {
			guardpointParamsPayload.PolicyID = string(guardpointParamsPlan.PolicyID.ValueString())
		}
		if guardpointParamsPlan.IsAutomountEnabled.ValueBool() != types.BoolNull().ValueBool() {
			guardpointParamsPayload.IsAutomountEnabled = bool(guardpointParamsPlan.IsAutomountEnabled.ValueBool())
		}
		if guardpointParamsPlan.IsCIFSEnabled.ValueBool() != types.BoolNull().ValueBool() {
			guardpointParamsPayload.IsCIFSEnabled = bool(guardpointParamsPlan.IsCIFSEnabled.ValueBool())
		}
		if guardpointParamsPlan.IsDataClassificationEnabled.ValueBool() != types.BoolNull().ValueBool() {
			guardpointParamsPayload.IsDataClassificationEnabled = bool(guardpointParamsPlan.IsDataClassificationEnabled.ValueBool())
		}
		if guardpointParamsPlan.IsDataLineageEnabled.ValueBool() != types.BoolNull().ValueBool() {
			guardpointParamsPayload.IsDataLineageEnabled = bool(guardpointParamsPlan.IsDataLineageEnabled.ValueBool())
		}
		if guardpointParamsPlan.DiskName.ValueString() != "" && guardpointParamsPlan.DiskName.ValueString() != types.StringNull().ValueString() {
			guardpointParamsPayload.DiskName = string(guardpointParamsPlan.DiskName.ValueString())
		}
		if guardpointParamsPlan.DiskgroupName.ValueString() != "" && guardpointParamsPlan.DiskgroupName.ValueString() != types.StringNull().ValueString() {
			guardpointParamsPayload.DiskgroupName = string(guardpointParamsPlan.DiskgroupName.ValueString())
		}
		if guardpointParamsPlan.IsEarlyAccessEnabled.ValueBool() != types.BoolNull().ValueBool() {
			guardpointParamsPayload.IsEarlyAccessEnabled = bool(guardpointParamsPlan.IsEarlyAccessEnabled.ValueBool())
		}
		if guardpointParamsPlan.IsIntelligentProtectionEnabled.ValueBool() != types.BoolNull().ValueBool() {
			guardpointParamsPayload.IsIntelligentProtectionEnabled = bool(guardpointParamsPlan.IsIntelligentProtectionEnabled.ValueBool())
		}
		if guardpointParamsPlan.IsDeviceIDTCapable.ValueBool() != types.BoolNull().ValueBool() {
			guardpointParamsPayload.IsDeviceIDTCapable = bool(guardpointParamsPlan.IsDeviceIDTCapable.ValueBool())
		}
		if guardpointParamsPlan.IsMFAEnabled.ValueBool() != types.BoolNull().ValueBool() {
			guardpointParamsPayload.IsMFAEnabled = bool(guardpointParamsPlan.IsMFAEnabled.ValueBool())
		}
		if guardpointParamsPlan.NWShareCredentialsID.ValueString() != "" && guardpointParamsPlan.NWShareCredentialsID.ValueString() != types.StringNull().ValueString() {
			guardpointParamsPayload.NWShareCredentialsID = string(guardpointParamsPlan.NWShareCredentialsID.ValueString())
		}
		if guardpointParamsPlan.PreserveSparseRegions.ValueBool() != types.BoolNull().ValueBool() {
			guardpointParamsPayload.PreserveSparseRegions = bool(guardpointParamsPlan.PreserveSparseRegions.ValueBool())
		}
		payload.GuardPointParams = &guardpointParamsPayload
	}

	for _, gp := range plan.GuardPaths {
		payload.GuardPaths = append(payload.GuardPaths, gp.ValueString())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_client_guardpoints.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Client Guardpoint Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(
		ctx,
		id,
		URL_CTE_CLIENT+"/"+plan.CTEClientID.ValueString()+"/guardpoints",
		payloadJSON,
		"guardpoints")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_client_guardpoints.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Client Guardpoint on CipherTrust Manager: ",
			"Could not create CTE Client Guardpoint, unexpected error: "+err.Error(),
		)
		return
	}

	//plan.UserID = types.StringValue(response)
	tflog.Debug(ctx, response)
	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cte_client_guardpoints.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEClientGP) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEClientGP) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan tfsdkUpdateGPModel
	var payload UpdateGPJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.IsDataClassificationEnabled.ValueBool() != types.BoolNull().ValueBool() {
		payload.IsDataClassificationEnabled = bool(plan.IsDataClassificationEnabled.ValueBool())
	}
	if plan.IsDataLineageEnabled.ValueBool() != types.BoolNull().ValueBool() {
		payload.IsDataLineageEnabled = bool(plan.IsDataLineageEnabled.ValueBool())
	}
	if plan.IsGuardEnabled.ValueBool() != types.BoolNull().ValueBool() {
		payload.IsGuardEnabled = bool(plan.IsGuardEnabled.ValueBool())
	}
	if plan.IsMFAEnabled.ValueBool() != types.BoolNull().ValueBool() {
		payload.IsMFAEnabled = bool(plan.IsMFAEnabled.ValueBool())
	}
	if plan.NWShareCredentialsID.ValueString() != "" && plan.NWShareCredentialsID.ValueString() != types.StringNull().ValueString() {
		payload.NWShareCredentialsID = string(plan.NWShareCredentialsID.ValueString())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_client_guardpoints.go -> Update]["+plan.GPID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Client Guardpoint Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(
		ctx,
		plan.GPID.ValueString(),
		URL_CTE_CLIENT+"/"+plan.CTEClientID.ValueString()+"/guardpoints",
		payloadJSON,
		"id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_client_guardpoints.go -> Update]["+plan.GPID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating CTE Client Guardpoint on CipherTrust Manager: ",
			"Could not update CTE Client Guardpoint, unexpected error: "+err.Error(),
		)
		return
	}
	plan.GPID = types.StringValue(response)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTEClientGP) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state tfsdkUpdateGPModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	output, err := r.client.DeleteByID(
		ctx,
		state.GPID.ValueString(),
		URL_CTE_CLIENT+"/"+state.CTEClientID.ValueString()+"/guardpoints")
	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cte_client_guardpoints.go -> Delete]["+state.GPID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust CTE Client Guardpoint",
			"Could not delete CTE Client Guardpoint, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTEClientGP) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Error in fetching client from provider",
			fmt.Sprintf("Expected *provider.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}
