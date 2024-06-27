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
	_ resource.Resource              = &resourceCTEPolicySignatureRule{}
	_ resource.ResourceWithConfigure = &resourceCTEPolicySignatureRule{}
)

func NewResourceCTEPolicySignatureRule() resource.Resource {
	return &resourceCTEPolicySignatureRule{}
}

type resourceCTEPolicySignatureRule struct {
	client *Client
}

func (r *resourceCTEPolicySignatureRule) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_policy_signature_rule"
}

// Schema defines the schema for the resource.
func (r *resourceCTEPolicySignatureRule) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"policy_id": schema.StringAttribute{
				Required:    true,
				Description: "ID of the parent policy in which Signature Rule need to be added",
			},
			"rule_id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the Signature Rule created in the parent policy",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"rule": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Signature Rule to be updated in the parent policy.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"signature_set_id_list": schema.ListAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "List of domainsList of identifiers of signature sets. The identifiers can be the Name, ID (a UUIDv4), URI, or slug of the signature sets.",
						},
						"signature_set_id": schema.StringAttribute{
							Optional:    true,
							Description: "An identifier of the signature set. This can be the Name, ID (a UUIDv4), URI, or slug of the signature set.",
						},
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEPolicySignatureRule) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, MSG_METHOD_START+"[resource_cte_policy_signaturerules.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan tfsdkAddSignatureRulePolicy
	var payload AddSignaturesToRuleJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	for _, signature := range plan.SignatureSetList {
		payload.SignatureSets = append(payload.SignatureSets, signature.ValueString())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_policy_signaturerules.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy Signature Rule Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(
		ctx,
		id,
		URL_CTE_POLICY+"/"+plan.CTEClientPolicyID.ValueString()+"/signaturerules",
		payloadJSON,
		"id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_policy_signaturerules.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Policy Signature Rule on CipherTrust Manager: ",
			"Could not create CTE Policy Signature Rule, unexpected error: "+err.Error(),
		)
		return
	}

	plan.SignatureRuleID = types.StringValue(response)

	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cte_policy_signaturerules.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEPolicySignatureRule) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEPolicySignatureRule) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan tfsdkAddSignatureRulePolicy
	var payload SignatureRuleJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.SignatureSetID.ValueString() != "" && plan.SignatureSetID.ValueString() != types.StringNull().ValueString() {
		payload.SignatureSetID = string(plan.SignatureSetID.ValueString())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_policy_signaturerules.go -> Update]["+plan.SignatureRuleID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy Signature Rule Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(
		ctx,
		plan.SignatureRuleID.ValueString(),
		URL_CTE_POLICY+"/"+plan.CTEClientPolicyID.ValueString()+"/signaturerules",
		payloadJSON,
		"id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_policy_signaturerules.go -> Update]["+plan.SignatureRuleID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating CTE Policy Signature Rule on CipherTrust Manager: ",
			"Could not update CTE Policy Signature Rule, unexpected error: "+err.Error(),
		)
		return
	}
	plan.SignatureRuleID = types.StringValue(response)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTEPolicySignatureRule) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state tfsdkAddSignatureRulePolicy
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	output, err := r.client.DeleteByID(
		ctx,
		state.SignatureRuleID.ValueString(),
		URL_CTE_POLICY+"/"+state.CTEClientPolicyID.ValueString()+"/signaturerules")
	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cte_policy_signaturerules.go -> Delete]["+state.SignatureRuleID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CTE Policy Signature Rule",
			"Could not delete CTE Policy Signature Rule, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTEPolicySignatureRule) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
