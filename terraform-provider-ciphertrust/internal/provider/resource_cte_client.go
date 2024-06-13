package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceCTEClient{}
	_ resource.ResourceWithConfigure = &resourceCTEClient{}
)

func NewResourceCTEClient() resource.Resource {
	return &resourceCTEClient{}
}

type resourceCTEClient struct {
	client *Client
}

func (r *resourceCTEClient) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_client"
}

// Schema defines the schema for the resource.
func (r *resourceCTEClient) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required: true,
			},
			"description": schema.StringAttribute{
				Optional: true,
			},
			"client_locked": schema.BoolAttribute{
				Optional: true,
			},
			"client_type": schema.StringAttribute{
				Optional: true,
			},
			"password": schema.StringAttribute{
				Optional: true,
			},
			"password_creation_method": schema.StringAttribute{
				Optional: true,
			},
			"profile_identifier": schema.StringAttribute{
				Optional: true,
			},
			"registration_allowed": schema.BoolAttribute{
				Optional: true,
			},
			"system_locked": schema.BoolAttribute{
				Optional: true,
			},
			"client_mfa_enabled": schema.BoolAttribute{
				Optional: true,
			},
			"del_client": schema.BoolAttribute{
				Optional: true,
			},
			"disable_capability": schema.StringAttribute{
				Optional: true,
			},
			"dynamic_parameters": schema.StringAttribute{
				Optional: true,
			},
			"enable_domain_sharing": schema.BoolAttribute{
				Optional: true,
			},
			"enabled_capabilities": schema.StringAttribute{
				Optional: true,
			},
			"lgcs_access_only": schema.BoolAttribute{
				Optional: true,
			},
			"max_num_cache_log": schema.Int64Attribute{
				Optional: true,
			},
			"max_space_cache_log": schema.Int64Attribute{
				Optional: true,
			},
			"profile_id": schema.StringAttribute{
				Optional: true,
			},
			"protection_mode": schema.StringAttribute{
				Optional: true,
			},
			"shared_domain_list": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEClient) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, MSG_METHOD_START+"[resource_cte_client.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan tfsdkCTEClientModel
	var payload CTEClientModelJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Name = trimString(plan.Name.ValueString())
	if plan.ClientLocked.ValueBool() != types.BoolNull().ValueBool() {
		payload.ClientLocked = plan.ClientLocked.ValueBool()
	}
	if plan.ClientType.ValueString() != "" && plan.ClientType.ValueString() != types.StringNull().ValueString() {
		payload.ClientType = trimString(plan.ClientType.String())
	}
	if plan.CommunicationEnabled.ValueBool() != types.BoolNull().ValueBool() {
		payload.CommunicationEnabled = plan.CommunicationEnabled.ValueBool()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = trimString(plan.Description.String())
	}
	if plan.Password.ValueString() != "" && plan.Password.ValueString() != types.StringNull().ValueString() {
		payload.Password = trimString(plan.Password.String())
	}
	if plan.PasswordCreationMethod.ValueString() != "" && plan.PasswordCreationMethod.ValueString() != types.StringNull().ValueString() {
		payload.PasswordCreationMethod = trimString(plan.PasswordCreationMethod.String())
	}
	if plan.ProfileIdentifier.ValueString() != "" && plan.ProfileIdentifier.ValueString() != types.StringNull().ValueString() {
		payload.ProfileIdentifier = trimString(plan.ProfileIdentifier.String())
	}
	if plan.RegistrationAllowed.ValueBool() != types.BoolNull().ValueBool() {
		payload.RegistrationAllowed = plan.RegistrationAllowed.ValueBool()
	}
	if plan.SystemLocked.ValueBool() != types.BoolNull().ValueBool() {
		payload.SystemLocked = plan.SystemLocked.ValueBool()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_client.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Client Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, id, URL_CTE_CLIENT, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_client.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Client on CipherTrust Manager: ",
			"Could not create CTE Client, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cte_client.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEClient) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEClient) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan tfsdkCTEClientModel
	var payload CTEClientModelJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.ClientLocked.ValueBool() != types.BoolNull().ValueBool() {
		payload.ClientLocked = plan.ClientLocked.ValueBool()
	}
	if plan.ClientType.ValueString() != "" && plan.ClientType.ValueString() != types.StringNull().ValueString() {
		payload.ClientType = trimString(plan.ClientType.String())
	}
	if plan.CommunicationEnabled.ValueBool() != types.BoolNull().ValueBool() {
		payload.CommunicationEnabled = plan.CommunicationEnabled.ValueBool()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = trimString(plan.Description.String())
	}
	if plan.Password.ValueString() != "" && plan.Password.ValueString() != types.StringNull().ValueString() {
		payload.Password = trimString(plan.Password.String())
	}
	if plan.PasswordCreationMethod.ValueString() != "" && plan.PasswordCreationMethod.ValueString() != types.StringNull().ValueString() {
		payload.PasswordCreationMethod = trimString(plan.PasswordCreationMethod.String())
	}
	if plan.RegistrationAllowed.ValueBool() != types.BoolNull().ValueBool() {
		payload.RegistrationAllowed = plan.RegistrationAllowed.ValueBool()
	}
	if plan.SystemLocked.ValueBool() != types.BoolNull().ValueBool() {
		payload.SystemLocked = plan.SystemLocked.ValueBool()
	}
	if plan.ClientMFAEnabled.ValueBool() != types.BoolNull().ValueBool() {
		payload.ClientMFAEnabled = plan.ClientMFAEnabled.ValueBool()
	}
	if plan.DelClient.ValueBool() != types.BoolNull().ValueBool() {
		payload.DelClient = plan.DelClient.ValueBool()
	}
	if plan.DisableCapability.ValueString() != "" && plan.DisableCapability.ValueString() != types.StringNull().ValueString() {
		payload.DisableCapability = trimString(plan.DisableCapability.String())
	}
	if plan.DynamicParameters.ValueString() != "" && plan.DynamicParameters.ValueString() != types.StringNull().ValueString() {
		payload.DynamicParameters = trimString(plan.DynamicParameters.String())
	}
	if plan.EnableDomainSharing.ValueBool() != types.BoolNull().ValueBool() {
		payload.EnableDomainSharing = plan.EnableDomainSharing.ValueBool()
	}
	if plan.EnabledCapabilities.ValueString() != "" && plan.EnabledCapabilities.ValueString() != types.StringNull().ValueString() {
		payload.EnabledCapabilities = trimString(plan.EnabledCapabilities.String())
	}
	if plan.LGCSAccessOnly.ValueBool() != types.BoolNull().ValueBool() {
		payload.LGCSAccessOnly = plan.LGCSAccessOnly.ValueBool()
	}
	if plan.MaxNumCacheLog.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.MaxNumCacheLog = plan.MaxNumCacheLog.ValueInt64()
	}
	if plan.MaxSpaceCacheLog.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.MaxSpaceCacheLog = plan.MaxSpaceCacheLog.ValueInt64()
	}
	if plan.ProfileID.ValueString() != "" && plan.ProfileID.ValueString() != types.StringNull().ValueString() {
		payload.ProfileID = trimString(plan.ProfileID.String())
	}
	if plan.ProtectionMode.ValueString() != "" && plan.ProtectionMode.ValueString() != types.StringNull().ValueString() {
		payload.ProtectionMode = trimString(plan.ProtectionMode.String())
	}
	if plan.SharedDomainList != nil {
		for _, domain := range plan.SharedDomainList {
			payload.SharedDomainList = append(payload.SharedDomainList, domain.ValueString())
		}
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_client.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Client Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(ctx, plan.ID.ValueString(), URL_CTE_CLIENT, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_client.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Client on CipherTrust Manager: ",
			"Could not update CTE Client, unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = types.StringValue(response)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTEClient) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state tfsdkCTEClientModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	output, err := r.client.DeleteByID(ctx, state.ID.ValueString(), URL_CTE_CLIENT)
	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cte_client.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust CTE Client",
			"Could not delete CTE Client, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTEClient) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
