package provider

import (
	"bytes"
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
	_ resource.Resource              = &resourceCMGroup{}
	_ resource.ResourceWithConfigure = &resourceCMGroup{}
)

func NewresourceCMGroup() resource.Resource {
	return &resourceCMGroup{}
}

type resourceCMGroup struct {
	client *Client
}

type tfsdkCMGroupModel struct {
	Name           types.String           `tfsdk:"name"`
	AppMetadata    map[string]interface{} `tfsdk:"app_metadata"`
	ClientMetadata map[string]interface{} `tfsdk:"client_metadata"`
	Description    types.String           `tfsdk:"description"`
	UserMetadata   map[string]interface{} `tfsdk:"user_metadata"`
}

func (r *resourceCMGroup) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_group"
}

// Schema defines the schema for the resource.
func (r *resourceCMGroup) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"app_metadata": schema.MapNestedAttribute{
				//ElementType: types.DynamicType,
				Optional: true,
			},
			"client_metadata": schema.MapNestedAttribute{
				//ElementType: types.DynamicType,
				Optional: true,
			},
			"description": schema.StringAttribute{
				Optional: true,
			},
			"user_metadata": schema.MapNestedAttribute{
				//ElementType: types.DynamicType,
				Optional: true,
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMGroup) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, MSG_METHOD_START+"[resource_cm_user.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan tfsdkCMGroupModel

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := map[string]interface{}{}
	payload["name"] = trimString(plan.Name.String())

	// appMetadataByte := new(bytes.Buffer)
	// for key, value := range plan.AppMetadata {
	// 	fmt.Fprintf(appMetadataByte, "%s=\"%s\"\n", key, value)
	// }

	appMetadataJSON := make(map[string]interface{})
	for key, value := range plan.AppMetadata {
		appMetadataJSON[key] = value
	}
	appMetadataJSONBytes, err := json.Marshal(appMetadataJSON)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error converting data to JSON",
			err.Error(),
		)
		return
	}
	payload["app_metadata"] = bytes.NewBuffer(appMetadataJSONBytes)

	clientMetadataJSON := make(map[string]interface{})
	for key, value := range plan.ClientMetadata {
		clientMetadataJSON[key] = value
	}
	clientMetadataJSONBytes, err := json.Marshal(clientMetadataJSON)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error converting data to JSON",
			err.Error(),
		)
		return
	}
	payload["client_metadata"] = bytes.NewBuffer(clientMetadataJSONBytes)

	payload["description"] = plan.Description.ValueString()

	userMetadataJSON := make(map[string]interface{})
	for key, value := range plan.UserMetadata {
		userMetadataJSON[key] = value
	}
	userMetadataJSONBytes, err := json.Marshal(userMetadataJSON)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error converting data to JSON",
			err.Error(),
		)
		return
	}
	payload["user_metadata"] = bytes.NewBuffer(userMetadataJSONBytes)

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Group Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, id, URL_GROUP, payloadJSON, "name")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating group on CipherTrust Manager: ",
			"Could not create group, unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "[resource_cm_user.go -> Create Output]["+response+"]")

	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cm_user.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMGroup) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMGroup) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	var plan tfsdkCMGroupModel

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := map[string]interface{}{}
	payload["name"] = trimString(plan.Name.String())

	appMetadataJSON := make(map[string]interface{})
	for key, value := range plan.AppMetadata {
		appMetadataJSON[key] = value
	}
	appMetadataJSONBytes, err := json.Marshal(appMetadataJSON)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error converting data to JSON",
			err.Error(),
		)
		return
	}
	payload["app_metadata"] = bytes.NewBuffer(appMetadataJSONBytes)

	clientMetadataJSON := make(map[string]interface{})
	for key, value := range plan.ClientMetadata {
		clientMetadataJSON[key] = value
	}
	clientMetadataJSONBytes, err := json.Marshal(clientMetadataJSON)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error converting data to JSON",
			err.Error(),
		)
		return
	}
	payload["client_metadata"] = bytes.NewBuffer(clientMetadataJSONBytes)

	payload["description"] = plan.Description.ValueString()

	userMetadataJSON := make(map[string]interface{})
	for key, value := range plan.UserMetadata {
		userMetadataJSON[key] = value
	}
	userMetadataJSONBytes, err := json.Marshal(userMetadataJSON)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error converting data to JSON",
			err.Error(),
		)
		return
	}
	payload["user_metadata"] = bytes.NewBuffer(userMetadataJSONBytes)

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Group Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(ctx, plan.Name.ValueString(), URL_GROUP, payloadJSON, "name")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_user.go -> Update]["+plan.Name.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating group on CipherTrust Manager: ",
			"Could not update group, unexpected error: "+err.Error(),
		)
		return
	}
	plan.Name = types.StringValue(response)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMGroup) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state tfsdkCMGroupModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	output, err := r.client.DeleteByID(ctx, state.Name.ValueString(), URL_GROUP)
	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cm_group.go -> Delete]["+state.Name.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust Group",
			"Could not delete group, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCMGroup) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
