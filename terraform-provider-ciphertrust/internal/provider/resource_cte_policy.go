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
	_ resource.Resource              = &resourceCTEPolicy{}
	_ resource.ResourceWithConfigure = &resourceCTEPolicy{}
)

func NewResourceCTEPolicy() resource.Resource {
	return &resourceCTEPolicy{}
}

type resourceCTEPolicy struct {
	client *Client
}

type DataTransformationRule struct {
	KeyID         types.String `tfsdk:"key_id"`
	KeyType       types.String `tfsdk:"key_type"`
	ResourceSetID types.String `tfsdk:"resource_set_id"`
}

type IDTKeyRule struct {
	CurrentKey            types.String `tfsdk:"current_key"`
	CurrentKeyType        types.String `tfsdk:"current_key_type"`
	TransformationKey     types.String `tfsdk:"transformation_key"`
	TransformationKeyType types.String `tfsdk:"transformation_key_type"`
}

type KeyRule struct {
	KeyID         types.String `tfsdk:"key_id"`
	KeyType       types.String `tfsdk:"key_type"`
	ResourceSetID types.String `tfsdk:"resource_set_id"`
}

type CurrentKey struct {
	KeyID   types.String `tfsdk:"key_id"`
	KeyType types.String `tfsdk:"key_type"`
}

type TransformationKey struct {
	KeyID   types.String `tfsdk:"key_id"`
	KeyType types.String `tfsdk:"key_type"`
}

type LDTKeyRule struct {
	CurrentKey        CurrentKey        `tfsdk:"current_key"`
	TransformationKey TransformationKey `tfsdk:"transformation_key"`
	IsExclusionRule   types.Bool        `tfsdk:"is_exclusion_rule"`
	ResourceSetID     types.String      `tfsdk:"resource_set_id"`
}

type CTEPolicyMetadata struct {
	RestrictUpdate types.Bool `tfsdk:"restrict_update"`
}

type SecurityRule struct {
	Action             types.String `tfsdk:"action"`
	Effect             types.String `tfsdk:"effect"`
	ExcludeProcessSet  types.Bool   `tfsdk:"exclude_process_set"`
	ExcludeResourceSet types.Bool   `tfsdk:"exclude_resource_set"`
	ExcludeUserSet     types.Bool   `tfsdk:"exclude_user_set"`
	PartialMatch       types.Bool   `tfsdk:"partial_match"`
	ProcessSetID       types.String `tfsdk:"process_set_id"`
	ResourceSetID      types.String `tfsdk:"resource_set_id"`
	UserSetID          types.String `tfsdk:"user_set_id"`
}

type SignatureRule struct {
	SignatureSetID types.String `tfsdk:"signature_set_id"`
}

type tfsdkCTEPolicyModel struct {
	ID                  types.String             `tfsdk:"id"`
	Name                types.String             `tfsdk:"name"`
	Description         types.String             `tfsdk:"description"`
	PolicyType          types.String             `tfsdk:"policy_type"`
	Metadata            CTEPolicyMetadata        `tfsdk:"metadata"`
	NeverDeny           types.Bool               `tfsdk:"never_deny"`
	DataTransformRules  []DataTransformationRule `tfsdk:"data_transform_rules"`
	IDTKeyRules         []IDTKeyRule             `tfsdk:"idt_key_rules"`
	KeyRules            []KeyRule                `tfsdk:"key_rules"`
	LDTKeyRules         []LDTKeyRule             `tfsdk:"ldt_key_rules"`
	SecurityRules       []SecurityRule           `tfsdk:"security_rules"`
	SignatureRules      []SignatureRule          `tfsdk:"signature_rules"`
	ForceRestrictUpdate types.Bool               `tfsdk:"force_restrict_update"`
}

func (r *resourceCTEPolicy) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_policy"
}

// Schema defines the schema for the resource.
func (r *resourceCTEPolicy) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
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
			"policy_type": schema.StringAttribute{
				Optional: true,
			},
			"data_transform_rules": schema.ListNestedAttribute{
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"key_id": schema.StringAttribute{
							Optional: true,
						},
						"key_type": schema.StringAttribute{
							Optional: true,
						},
						"resource_set_id": schema.StringAttribute{
							Optional: true,
						},
					},
				},
			},
			"description": schema.StringAttribute{
				Optional: true,
			},
			"idt_key_rules": schema.ListNestedAttribute{
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"current_key": schema.StringAttribute{
							Optional: true,
						},
						"current_key_type": schema.StringAttribute{
							Optional: true,
						},
						"transformation_key": schema.StringAttribute{
							Optional: true,
						},
						"transformation_key_type": schema.StringAttribute{
							Optional: true,
						},
					},
				},
			},
			"key_rules": schema.ListNestedAttribute{
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"key_id": schema.StringAttribute{
							Optional: true,
						},
						"key_type": schema.StringAttribute{
							Optional: true,
						},
						"resource_set_id": schema.StringAttribute{
							Optional: true,
						},
					},
				},
			},
			"ldt_key_rules": schema.ListNestedAttribute{
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"is_exclusion_rule": schema.BoolAttribute{
							Optional: true,
						},
						"resource_set_id": schema.StringAttribute{
							Optional: true,
						},
						"current_key": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"key_id": schema.StringAttribute{
										Optional: true,
									},
									"key_type": schema.StringAttribute{
										Optional: true,
									},
								},
							},
						},
						"transformation_key": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"key_id": schema.StringAttribute{
										Optional: true,
									},
									"key_type": schema.StringAttribute{
										Optional: true,
									},
								},
							},
						},
					},
				},
			},
			"metadata": schema.MapNestedAttribute{
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"restrict_update": schema.BoolAttribute{
							Optional: true,
						},
					},
				},
			},
			"never_deny": schema.BoolAttribute{
				Optional: true,
			},
			"security_rules": schema.ListNestedAttribute{
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"action": schema.StringAttribute{
							Optional: true,
						},
						"effect": schema.StringAttribute{
							Optional: true,
						},
						"exclude_process_set": schema.BoolAttribute{
							Optional: true,
						},
						"exclude_resource_set": schema.BoolAttribute{
							Optional: true,
						},
						"exclude_user_set": schema.BoolAttribute{
							Optional: true,
						},
						"partial_match": schema.BoolAttribute{
							Optional: true,
						},
						"process_set_id": schema.StringAttribute{
							Optional: true,
						},
						"resource_set_id": schema.StringAttribute{
							Optional: true,
						},
						"user_set_id": schema.StringAttribute{
							Optional: true,
						},
					},
				},
			},
			"signature_rules": schema.ListNestedAttribute{
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"signature_set_id": schema.StringAttribute{
							Optional: true,
						},
					},
				},
			},
			"force_restrict_update": schema.BoolAttribute{
				Optional: true,
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEPolicy) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, MSG_METHOD_START+"[resource_cte_policy.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan tfsdkCTEPolicyModel
	var payload CTEPolicyModelJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Add Name to the payload
	payload.Name = trimString(plan.Name.String())

	// Add Policy Type to the payload
	payload.PolicyType = trimString(plan.PolicyType.String())

	// Add Description to the payload if set
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = trimString(plan.Description.String())
	}

	// Add never_deny to the payload if set
	if plan.NeverDeny.ValueBool() != types.BoolNull().ValueBool() {
		payload.NeverDeny = bool(plan.NeverDeny.ValueBool())
	}

	// Add Data Transformation Rules to the payload if set
	var txRules []DataTxRuleJSON
	for _, txRule := range plan.DataTransformRules {
		var txRuleJSON DataTxRuleJSON
		if txRule.KeyID.ValueString() != "" && txRule.KeyID.ValueString() != types.StringNull().ValueString() {
			txRuleJSON.KeyID = string(txRule.KeyID.ValueString())
		}
		if txRule.KeyType.ValueString() != "" && txRule.KeyType.ValueString() != types.StringNull().ValueString() {
			txRuleJSON.KeyType = string(txRule.KeyType.ValueString())
		}
		if txRule.ResourceSetID.ValueString() != "" && txRule.ResourceSetID.ValueString() != types.StringNull().ValueString() {
			txRuleJSON.ResourceSetID = string(txRule.ResourceSetID.ValueString())
		}
		txRules = append(txRules, txRuleJSON)
	}
	payload.DataTransformRules = txRules

	// Add Data Transformation Rules to the payload if set
	var IDTKeyRules []IDTRuleJSON
	for _, IDTKeyRule := range plan.IDTKeyRules {
		var IDTKeyRuleJSON IDTRuleJSON
		if IDTKeyRule.CurrentKey.ValueString() != "" && IDTKeyRule.CurrentKey.ValueString() != types.StringNull().ValueString() {
			IDTKeyRuleJSON.CurrentKey = string(IDTKeyRule.CurrentKey.ValueString())
		}
		if IDTKeyRule.CurrentKeyType.ValueString() != "" && IDTKeyRule.CurrentKeyType.ValueString() != types.StringNull().ValueString() {
			IDTKeyRuleJSON.CurrentKeyType = string(IDTKeyRule.CurrentKeyType.ValueString())
		}
		if IDTKeyRule.TransformationKey.ValueString() != "" && IDTKeyRule.TransformationKey.ValueString() != types.StringNull().ValueString() {
			IDTKeyRuleJSON.TransformationKey = string(IDTKeyRule.TransformationKey.ValueString())
		}
		if IDTKeyRule.TransformationKeyType.ValueString() != "" && IDTKeyRule.TransformationKeyType.ValueString() != types.StringNull().ValueString() {
			IDTKeyRuleJSON.TransformationKeyType = string(IDTKeyRule.TransformationKeyType.ValueString())
		}
		IDTKeyRules = append(IDTKeyRules, IDTKeyRuleJSON)
	}
	payload.IDTKeyRules = IDTKeyRules

	// Add Key Rules to the payload if set
	var keyRules []KeyRuleJSON
	for _, keyRule := range plan.KeyRules {
		var keyRuleJSON KeyRuleJSON
		if keyRule.KeyID.ValueString() != "" && keyRule.KeyID.ValueString() != types.StringNull().ValueString() {
			keyRuleJSON.KeyID = string(keyRule.KeyID.ValueString())
		}
		if keyRule.KeyType.ValueString() != "" && keyRule.KeyType.ValueString() != types.StringNull().ValueString() {
			keyRuleJSON.KeyType = string(keyRule.KeyType.ValueString())
		}
		if keyRule.ResourceSetID.ValueString() != "" && keyRule.ResourceSetID.ValueString() != types.StringNull().ValueString() {
			keyRuleJSON.ResourceSetID = string(keyRule.ResourceSetID.ValueString())
		}
		keyRules = append(keyRules, keyRuleJSON)
	}
	payload.KeyRules = keyRules

	var metadata CTEPolicyMetadataJSON
	if plan.Metadata.RestrictUpdate.ValueBool() != types.BoolNull().ValueBool() {
		metadata.RestrictUpdate = bool(plan.Metadata.RestrictUpdate.ValueBool())
	}
	payload.Metadata = metadata

	// Add Key Rules to the payload if set
	var ldtKeyRules []LDTRuleJSON
	for _, ldtKeyRule := range plan.LDTKeyRules {
		var ldtKeyRuleJSON LDTRuleJSON
		var ldtKeyRuleCurrentKey CurrentKeyJSON
		var ldtKeyRuleTransformationKey TransformationKeyJSON
		if ldtKeyRule.ResourceSetID.ValueString() != "" && ldtKeyRule.ResourceSetID.ValueString() != types.StringNull().ValueString() {
			ldtKeyRuleJSON.ResourceSetID = string(ldtKeyRule.ResourceSetID.ValueString())
		}
		if ldtKeyRule.IsExclusionRule.ValueBool() != types.BoolNull().ValueBool() {
			ldtKeyRuleJSON.IsExclusionRule = bool(ldtKeyRule.IsExclusionRule.ValueBool())
		}
		if ldtKeyRule.CurrentKey.KeyID.ValueString() != "" && ldtKeyRule.CurrentKey.KeyID.ValueString() != types.StringNull().ValueString() {
			ldtKeyRuleCurrentKey.KeyID = string(ldtKeyRule.CurrentKey.KeyID.ValueString())
		}
		if ldtKeyRule.CurrentKey.KeyType.ValueString() != "" && ldtKeyRule.CurrentKey.KeyType.ValueString() != types.StringNull().ValueString() {
			ldtKeyRuleCurrentKey.KeyType = string(ldtKeyRule.CurrentKey.KeyType.ValueString())
		}
		if ldtKeyRule.TransformationKey.KeyID.ValueString() != "" && ldtKeyRule.TransformationKey.KeyID.ValueString() != types.StringNull().ValueString() {
			ldtKeyRuleTransformationKey.KeyID = string(ldtKeyRule.TransformationKey.KeyID.ValueString())
		}
		if ldtKeyRule.TransformationKey.KeyType.ValueString() != "" && ldtKeyRule.TransformationKey.KeyType.ValueString() != types.StringNull().ValueString() {
			ldtKeyRuleTransformationKey.KeyType = string(ldtKeyRule.TransformationKey.KeyType.ValueString())
		}
		ldtKeyRuleJSON.CurrentKey = ldtKeyRuleCurrentKey
		ldtKeyRuleJSON.TransformationKey = ldtKeyRuleTransformationKey
		ldtKeyRules = append(ldtKeyRules, ldtKeyRuleJSON)
	}
	payload.LDTKeyRules = ldtKeyRules

	// Add Security Rules to the payload if set
	var securityRules []SecurityRuleJSON
	for _, securityRule := range plan.SecurityRules {
		var securityRuleJSON SecurityRuleJSON
		if securityRule.Action.ValueString() != "" && securityRule.Action.ValueString() != types.StringNull().ValueString() {
			securityRuleJSON.Action = string(securityRule.Action.ValueString())
		}
		if securityRule.Effect.ValueString() != "" && securityRule.Effect.ValueString() != types.StringNull().ValueString() {
			securityRuleJSON.Effect = string(securityRule.Effect.ValueString())
		}
		if securityRule.ExcludeProcessSet.ValueBool() != types.BoolNull().ValueBool() {
			securityRuleJSON.ExcludeProcessSet = bool(securityRule.ExcludeProcessSet.ValueBool())
		}
		if securityRule.ExcludeUserSet.ValueBool() != types.BoolNull().ValueBool() {
			securityRuleJSON.ExcludeUserSet = bool(securityRule.ExcludeUserSet.ValueBool())
		}
		if securityRule.ExcludeResourceSet.ValueBool() != types.BoolNull().ValueBool() {
			securityRuleJSON.ExcludeResourceSet = bool(securityRule.ExcludeResourceSet.ValueBool())
		}
		if securityRule.PartialMatch.ValueBool() != types.BoolNull().ValueBool() {
			securityRuleJSON.PartialMatch = bool(securityRule.PartialMatch.ValueBool())
		}
		if securityRule.ProcessSetID.ValueString() != "" && securityRule.ProcessSetID.ValueString() != types.StringNull().ValueString() {
			securityRuleJSON.ProcessSetID = string(securityRule.ProcessSetID.ValueString())
		}
		if securityRule.ResourceSetID.ValueString() != "" && securityRule.ResourceSetID.ValueString() != types.StringNull().ValueString() {
			securityRuleJSON.ResourceSetID = string(securityRule.ResourceSetID.ValueString())
		}
		if securityRule.UserSetID.ValueString() != "" && securityRule.UserSetID.ValueString() != types.StringNull().ValueString() {
			securityRuleJSON.UserSetID = string(securityRule.UserSetID.ValueString())
		}
		securityRules = append(securityRules, securityRuleJSON)
	}
	payload.SecurityRules = securityRules

	// Add Signature Rules to the payload if set
	var signatureRules []SignatureRuleJSON
	for _, signatureRule := range plan.SignatureRules {
		var signatureRuleJSON SignatureRuleJSON
		if signatureRule.SignatureSetID.ValueString() != "" && signatureRule.SignatureSetID.ValueString() != types.StringNull().ValueString() {
			signatureRuleJSON.SignatureSetID = string(signatureRule.SignatureSetID.ValueString())
		}
		signatureRules = append(signatureRules, signatureRuleJSON)
	}
	payload.SignatureRules = signatureRules

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_policy.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, id, URL_CTE_POLICY, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_policy.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Policy on CipherTrust Manager: ",
			"Could not create CTE Policy, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cte_policy.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEPolicy) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEPolicy) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan tfsdkCTEPolicyModel
	var payload CTEPolicyModelJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Add Description to the payload if set
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = trimString(plan.Description.String())
	}

	// Add never_deny to the payload if set
	if plan.NeverDeny.ValueBool() != types.BoolNull().ValueBool() {
		payload.NeverDeny = bool(plan.NeverDeny.ValueBool())
	}

	// Add never_deny to the payload if set
	if plan.ForceRestrictUpdate.ValueBool() != types.BoolNull().ValueBool() {
		payload.ForceRestrictUpdate = bool(plan.ForceRestrictUpdate.ValueBool())
	}

	var metadata CTEPolicyMetadataJSON
	if plan.Metadata.RestrictUpdate.ValueBool() != types.BoolNull().ValueBool() {
		metadata.RestrictUpdate = bool(plan.Metadata.RestrictUpdate.ValueBool())
	}
	payload.Metadata = metadata

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_policy.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(ctx, plan.ID.ValueString(), URL_CTE_POLICY, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_policy.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Policy on CipherTrust Manager: ",
			"Could not create CTE Policy, unexpected error: "+err.Error(),
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
func (r *resourceCTEPolicy) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state tfsdkCTEPolicyModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	output, err := r.client.DeleteByID(ctx, state.ID.ValueString(), URL_CTE_POLICY)
	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cte_policy.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CTE Policy",
			"Could not delete CTE Policy, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTEPolicy) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
