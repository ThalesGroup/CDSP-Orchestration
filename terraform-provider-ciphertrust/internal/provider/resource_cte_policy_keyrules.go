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
	_ resource.Resource              = &resourceCTEPolicyKeyRule{}
	_ resource.ResourceWithConfigure = &resourceCTEPolicyKeyRule{}
)

func NewResourceCTEPolicyKeyRule() resource.Resource {
	return &resourceCTEPolicyKeyRule{}
}

type resourceCTEPolicyKeyRule struct {
	client *Client
}

func (r *resourceCTEPolicyKeyRule) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_policy_key_rule"
}

// Schema defines the schema for the resource.
func (r *resourceCTEPolicyKeyRule) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"policy_id": schema.StringAttribute{
				Required:    true,
				Description: "ID of the parent policy in which Key Rule need to be added",
			},
			"rule_id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the Key Rule created in the parent policy",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"order_number": schema.Int64Attribute{
				Optional:    true,
				Description: "Precedence order of the rule in the parent policy.",
			},
			"rule": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Key rule to be updated in the parent policy.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"key_id": schema.StringAttribute{
							Optional:    true,
							Description: "Identifier of the key to link with the rule. Supported fields are name, id, slug, alias, uri, uuid, muid, and key_id. Note: For decryption, where a clear key is to be supplied, use the string \"clear_key\" only. Do not specify any other identifier.",
						},
						"key_type": schema.StringAttribute{
							Optional:    true,
							Description: "Specify the type of the key. Must be one of name, id, slug, alias, uri, uuid, muid or key_id. If not specified, the type of the key is inferred.",
						},
						"resource_set_id": schema.StringAttribute{
							Optional:    true,
							Description: "ID of the resource set to link with the rule. Supported for Standard, LDT and IDT policies.",
						},
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEPolicyKeyRule) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, MSG_METHOD_START+"[resource_cte_policy_keyrules.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan tfsdkAddKeyRulePolicy
	var payload KeyRuleJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.KeyRule.KeyID.ValueString() != "" && plan.KeyRule.KeyID.ValueString() != types.StringNull().ValueString() {
		payload.KeyID = string(plan.KeyRule.KeyID.ValueString())
	}
	if plan.KeyRule.KeyType.ValueString() != "" && plan.KeyRule.KeyType.ValueString() != types.StringNull().ValueString() {
		payload.KeyType = string(plan.KeyRule.KeyType.ValueString())
	}
	if plan.KeyRule.ResourceSetID.ValueString() != "" && plan.KeyRule.ResourceSetID.ValueString() != types.StringNull().ValueString() {
		payload.ResourceSetID = string(plan.KeyRule.ResourceSetID.ValueString())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_policy_keyrules.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy Key Rule Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(
		ctx,
		id,
		URL_CTE_POLICY+"/"+plan.CTEClientPolicyID.ValueString()+"/keyrules",
		payloadJSON,
		"id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_policy_keyrules.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Policy Key Rule on CipherTrust Manager: ",
			"Could not create CTE Policy Key Rule, unexpected error: "+err.Error(),
		)
		return
	}

	plan.KeyRuleID = types.StringValue(response)

	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cte_policy_keyrules.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEPolicyKeyRule) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEPolicyKeyRule) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan tfsdkAddKeyRulePolicy
	var payload KeyRuleUpdateJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.KeyRule.KeyID.ValueString() != "" && plan.KeyRule.KeyID.ValueString() != types.StringNull().ValueString() {
		payload.KeyID = string(plan.KeyRule.KeyID.ValueString())
	}
	if plan.KeyRule.KeyType.ValueString() != "" && plan.KeyRule.KeyType.ValueString() != types.StringNull().ValueString() {
		payload.KeyType = string(plan.KeyRule.KeyType.ValueString())
	}
	if plan.KeyRule.ResourceSetID.ValueString() != "" && plan.KeyRule.ResourceSetID.ValueString() != types.StringNull().ValueString() {
		payload.ResourceSetID = string(plan.KeyRule.ResourceSetID.ValueString())
	}
	if plan.OrderNumber.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.OrderNumber = int64(plan.OrderNumber.ValueInt64())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_policy_keyrules.go -> Update]["+plan.KeyRuleID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy Key Rule Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(
		ctx,
		plan.KeyRuleID.ValueString(),
		URL_CTE_POLICY+"/"+plan.CTEClientPolicyID.ValueString()+"/keyrules",
		payloadJSON,
		"id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_policy_keyrules.go -> Update]["+plan.KeyRuleID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating CTE Policy Key Rule on CipherTrust Manager: ",
			"Could not update CTE Policy Key Rule, unexpected error: "+err.Error(),
		)
		return
	}
	plan.KeyRuleID = types.StringValue(response)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTEPolicyKeyRule) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state tfsdkAddKeyRulePolicy
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	output, err := r.client.DeleteByID(
		ctx,
		state.KeyRuleID.ValueString(),
		URL_CTE_POLICY+"/"+state.CTEClientPolicyID.ValueString()+"/keyrules")
	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cte_policy_keyrules.go -> Delete]["+state.KeyRuleID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CTE Policy",
			"Could not delete CTE Policy, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTEPolicyKeyRule) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
