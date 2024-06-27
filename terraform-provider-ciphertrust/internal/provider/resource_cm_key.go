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
	_ resource.Resource              = &resourceCMKey{}
	_ resource.ResourceWithConfigure = &resourceCMKey{}
)

func NewResourceCMKey() resource.Resource {
	return &resourceCMKey{}
}

type resourceCMKey struct {
	client *Client
}

func (r *resourceCMKey) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_key"
}

// Schema defines the schema for the resource.
func (r *resourceCMKey) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"activation_date": schema.StringAttribute{
				Optional: true,
			},
			"algorithm": schema.StringAttribute{
				Optional: true,
			},
			"archive_date": schema.StringAttribute{
				Optional: true,
			},
			"assign_self_as_owner": schema.BoolAttribute{
				Optional: true,
			},
			"cert_type": schema.StringAttribute{
				Optional: true,
			},
			"compromise_date": schema.StringAttribute{
				Optional: true,
			},
			"compromise_occurrence_date": schema.StringAttribute{
				Optional: true,
			},
			"curveid": schema.StringAttribute{
				Optional: true,
			},
			"deactivation_date": schema.StringAttribute{
				Optional: true,
			},
			"default_iv": schema.StringAttribute{
				Optional: true,
			},
			"description": schema.StringAttribute{
				Optional: true,
			},
			"destroy_date": schema.StringAttribute{
				Optional: true,
			},
			"empty_material": schema.BoolAttribute{
				Optional: true,
			},
			"encoding": schema.StringAttribute{
				Optional: true,
			},
			"format": schema.StringAttribute{
				Optional: true,
			},
			"generate_key_id": schema.BoolAttribute{
				Optional: true,
			},
			"hkdf_create_parameters": schema.SingleNestedAttribute{
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"hash_algorithm": schema.StringAttribute{
						Optional: true,
					},
					"ikm_key_name": schema.StringAttribute{
						Optional: true,
					},
					"info": schema.StringAttribute{
						Optional: true,
					},
					"salt": schema.StringAttribute{
						Optional: true,
					},
				},
			},
			"id_size": schema.Int64Attribute{
				Optional: true,
			},
			"key_id": schema.StringAttribute{
				Optional: true,
			},
			"mac_sign_bytes": schema.StringAttribute{
				Optional: true,
			},
			"mac_sign_key_identifier": schema.StringAttribute{
				Optional: true,
			},
			"mac_sign_key_identifier_type": schema.StringAttribute{
				Optional: true,
			},
			"material": schema.StringAttribute{
				Optional: true,
			},
			"muid": schema.StringAttribute{
				Optional: true,
			},
			"object_type": schema.StringAttribute{
				Optional: true,
			},
			"name": schema.StringAttribute{
				Optional: true,
			},
			"meta": schema.SingleNestedAttribute{
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"owner_id": schema.StringAttribute{
						Optional: true,
					},
				},
			},
			"padded": schema.BoolAttribute{
				Optional: true,
			},
			"password": schema.StringAttribute{
				Optional: true,
			},
			"process_start_date": schema.StringAttribute{
				Optional: true,
			},
			"protect_stop_date": schema.StringAttribute{
				Optional: true,
			},
			"revocation_reason": schema.StringAttribute{
				Optional: true,
			},
			"revocation_message": schema.StringAttribute{
				Optional: true,
			},
			"rotation_frequency_days": schema.StringAttribute{
				Optional: true,
			},
			"secret_data_encoding": schema.StringAttribute{
				Optional: true,
			},
			"secret_data_link": schema.StringAttribute{
				Optional: true,
			},
			"signing_algo": schema.StringAttribute{
				Optional: true,
			},
			"size": schema.Int64Attribute{
				Optional: true,
			},
			"unexportable": schema.BoolAttribute{
				Optional: true,
			},
			"undeletable": schema.BoolAttribute{
				Optional: true,
			},
			"state": schema.StringAttribute{
				Optional: true,
			},
			"usage_mask": schema.Int64Attribute{
				Optional: true,
			},
			"uuid": schema.StringAttribute{
				Optional: true,
			},
			"wrap_key_id_type": schema.StringAttribute{
				Optional: true,
			},
			"wrap_key_name": schema.StringAttribute{
				Optional: true,
			},
			"wrap_public_key": schema.StringAttribute{
				Optional: true,
			},
			"wrap_public_key_padding": schema.StringAttribute{
				Optional: true,
			},
			"wrapping_encryption_algo": schema.StringAttribute{
				Optional: true,
			},
			"wrapping_hash_algo": schema.StringAttribute{
				Optional: true,
			},
			"wrapping_method": schema.StringAttribute{
				Optional: true,
			},
			"xts": schema.BoolAttribute{
				Optional: true,
			},
			"aliases": schema.ListNestedAttribute{
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"alias": schema.StringAttribute{
							Required: true,
						},
						"index": schema.Int64Attribute{
							Required: true,
						},
						"type": schema.StringAttribute{
							Required: true,
						},
					},
				},
			},
			"public_key_parameters": schema.SingleNestedAttribute{
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"activation_date": schema.StringAttribute{
						Optional: true,
					},
					"archive_date": schema.StringAttribute{
						Optional: true,
					},
					"deactivation_date": schema.StringAttribute{
						Optional: true,
					},
					"name": schema.StringAttribute{
						Optional: true,
					},
					"state": schema.StringAttribute{
						Optional: true,
					},
					"undeletable": schema.BoolAttribute{
						Optional: true,
					},
					"unexportable": schema.BoolAttribute{
						Optional: true,
					},
					"usage_mask": schema.Int64Attribute{
						Optional: true,
					},
					"aliases": schema.ListNestedAttribute{
						Optional: true,
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"alias": schema.StringAttribute{
									Required: true,
								},
								"index": schema.Int64Attribute{
									Required: true,
								},
								"type": schema.StringAttribute{
									Required: true,
								},
							},
						},
					},
				},
			},
			"wrap_hkdf": schema.SingleNestedAttribute{
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"hash_algorithm": schema.StringAttribute{
						Optional: true,
					},
					"okm_len": schema.Int64Attribute{
						Optional: true,
					},
					"info": schema.StringAttribute{
						Optional: true,
					},
					"salt": schema.StringAttribute{
						Optional: true,
					},
				},
			},
			"wrap_pbe": schema.SingleNestedAttribute{
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"dklen": schema.Int64Attribute{
						Optional: true,
					},
					"hash_algorithm": schema.StringAttribute{
						Optional: true,
					},
					"salt": schema.StringAttribute{
						Optional: true,
					},
					"iteration": schema.Int64Attribute{
						Optional: true,
					},
					"password": schema.StringAttribute{
						Optional: true,
					},
					"password_identifier": schema.StringAttribute{
						Optional: true,
					},
					"password_identifier_type": schema.StringAttribute{
						Optional: true,
					},
					"purpose": schema.StringAttribute{
						Optional: true,
					},
				},
			},
			"wrap_rsaaes": schema.SingleNestedAttribute{
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"aes_key_size": schema.Int64Attribute{
						Optional: true,
					},
					"padding": schema.StringAttribute{
						Optional: true,
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMKey) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, MSG_METHOD_START+"[resource_cm_key.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan tfsdkCMKeyModel
	payload := map[string]interface{}{}

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload["name"] = trimString(plan.Name.String())
	payload["algorithm"] = trimString(plan.Algorithm.String())
	payload["size"] = plan.Size.ValueInt64()
	payload["usageMask"] = plan.UsageMask.ValueInt64()

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_key.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Key Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, id, URL_KEY_MANAGEMENT, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_key.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating key on CipherTrust Manager: ",
			"Could not create key, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cm_key.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMKey) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMKey) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan tfsdkCMKeyModel
	payload := map[string]interface{}{}

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload["description"] = trimString(plan.Description.String())

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_key.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Key Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(ctx, plan.ID.ValueString(), URL_KEY_MANAGEMENT, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_key.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating key on CipherTrust Manager: ",
			"Could not upodate key, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cm_key.go -> Update]["+plan.ID.ValueString()+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMKey) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state tfsdkCMKeyModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	output, err := r.client.DeleteByID(ctx, state.ID.ValueString(), URL_KEY_MANAGEMENT)
	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cm_key.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust Key",
			"Could not delete key, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCMKey) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
