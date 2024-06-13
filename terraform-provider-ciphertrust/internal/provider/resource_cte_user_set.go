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
	_ resource.Resource              = &resourceCTEUserSet{}
	_ resource.ResourceWithConfigure = &resourceCTEUserSet{}
)

func NewResourceCTEUserSet() resource.Resource {
	return &resourceCTEUserSet{}
}

type resourceCTEUserSet struct {
	client *Client
}

func (r *resourceCTEUserSet) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_user_set"
}

// Schema defines the schema for the resource.
func (r *resourceCTEUserSet) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
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
			"users": schema.ListNestedAttribute{
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"gid": schema.Int64Attribute{
							Optional: true,
						},
						"gname": schema.StringAttribute{
							Optional: true,
						},
						"os_domain": schema.StringAttribute{
							Optional: true,
						},
						"uid": schema.Int64Attribute{
							Optional: true,
						},
						"uname": schema.StringAttribute{
							Optional: true,
						},
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEUserSet) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, MSG_METHOD_START+"[resource_cm_user_set.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan tfsdkCTEUserSetModel
	payload := map[string]interface{}{}

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload["name"] = trimString(plan.Name.String())
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload["description"] = trimString(plan.Description.String())
	}
	var usersJSONArr []CTEUserJSON
	for _, user := range plan.Users {
		var userJSON CTEUserJSON
		if user.GID.ValueInt64() != types.Int64Null().ValueInt64() {
			userJSON.GID = int(user.GID.ValueInt64())
		}
		if user.GID.ValueInt64() != types.Int64Null().ValueInt64() {
			userJSON.UID = int(user.UID.ValueInt64())
		}
		if user.OSDomain.ValueString() != "" && user.OSDomain.ValueString() != types.StringNull().ValueString() {
			userJSON.OSDomain = string(user.OSDomain.ValueString())
		}
		if user.UName.ValueString() != "" && user.UName.ValueString() != types.StringNull().ValueString() {
			userJSON.UName = string(user.UName.ValueString())
		}
		if user.GName.ValueString() != "" && user.GName.ValueString() != types.StringNull().ValueString() {
			userJSON.GName = string(user.GName.ValueString())
		}

		usersJSONArr = append(usersJSONArr, userJSON)
	}
	payload["users"] = usersJSONArr

	payloadJSON, _ := json.Marshal(payload)

	response, err := r.client.PostData(ctx, id, URL_CTE_USER_SET, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_user_set.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE User Set on CipherTrust Manager: ",
			"Could not create CTE User Set, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cm_user_set.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEUserSet) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEUserSet) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan tfsdkCTEUserSetModel
	payload := map[string]interface{}{}

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload["description"] = trimString(plan.Description.String())
	}
	var usersJSONArr []CTEUserJSON
	for _, user := range plan.Users {
		var userJSON CTEUserJSON
		if user.GID.ValueInt64() != types.Int64Null().ValueInt64() {
			userJSON.GID = int(user.GID.ValueInt64())
		}
		if user.GID.ValueInt64() != types.Int64Null().ValueInt64() {
			userJSON.UID = int(user.UID.ValueInt64())
		}
		if user.OSDomain.ValueString() != "" && user.OSDomain.ValueString() != types.StringNull().ValueString() {
			userJSON.OSDomain = string(user.OSDomain.ValueString())
		}
		if user.UName.ValueString() != "" && user.UName.ValueString() != types.StringNull().ValueString() {
			userJSON.UName = string(user.UName.ValueString())
		}
		if user.GName.ValueString() != "" && user.GName.ValueString() != types.StringNull().ValueString() {
			userJSON.GName = string(user.GName.ValueString())
		}

		usersJSONArr = append(usersJSONArr, userJSON)
	}
	payload["users"] = usersJSONArr

	payloadJSON, _ := json.Marshal(payload)

	response, err := r.client.UpdateData(ctx, plan.ID.ValueString(), URL_CTE_USER_SET, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_user_set.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE User Set on CipherTrust Manager: ",
			"Could not create CTE User Set, unexpected error: "+err.Error(),
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
func (r *resourceCTEUserSet) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state tfsdkCTEUserSetModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	output, err := r.client.DeleteByID(ctx, state.ID.ValueString(), URL_CTE_USER_SET)
	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cm_user_set.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CTE User Set",
			"Could not delete CTE User Set, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTEUserSet) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
