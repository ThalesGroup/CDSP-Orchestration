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
	_ resource.Resource              = &resourceCTEResourceSet{}
	_ resource.ResourceWithConfigure = &resourceCTEResourceSet{}
)

func NewResourceCTEResourceSet() resource.Resource {
	return &resourceCTEResourceSet{}
}

type resourceCTEResourceSet struct {
	client *Client
}

type ClassificationTagAttributes struct {
	DataType types.String `tfsdk:"data_type"`
	Name     types.String `tfsdk:"name"`
	Operator types.String `tfsdk:"operator"`
	Value    types.String `tfsdk:"value"`
}

type ClassificationTag struct {
	Description types.String                  `tfsdk:"description"`
	Name        types.String                  `tfsdk:"name"`
	Attributes  []ClassificationTagAttributes `tfsdk:"attributes"`
}

type CTEResource struct {
	Directory         types.Int64  `tfsdk:"directory"`
	File              types.String `tfsdk:"file"`
	HDFS              types.String `tfsdk:"hdfs"`
	IncludeSubfolders types.Int64  `tfsdk:"include_subfolders"`
}

type tfsdkCTEResourceSetModel struct {
	ID                 types.String        `tfsdk:"id"`
	Name               types.String        `tfsdk:"name"`
	Description        types.String        `tfsdk:"description"`
	Resources          []CTEResource       `tfsdk:"resources"`
	Type               types.String        `tfsdk:"type"`
	ClassificationTags []ClassificationTag `tfsdk:"classification_tags"`
}

func (r *resourceCTEResourceSet) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_resource_set"
}

// Schema defines the schema for the resource.
func (r *resourceCTEResourceSet) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
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
						"gname": schema.Int64Attribute{
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
func (r *resourceCTEResourceSet) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, MSG_METHOD_START+"[resource_cm_resource_set.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan tfsdkCTEResourceSetModel
	payload := map[string]interface{}{}

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload["name"] = trimString(plan.Name.String())
	payload["description"] = trimString(plan.Description.String())
	payload["resources"] = plan.Resources

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_resource_set.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Resource Set Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, id, URL_CTE_RESOURCE_SET, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_resource_set.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Resource Set on CipherTrust Manager: ",
			"Could not create CTE Resource Set, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cm_resource_set.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEResourceSet) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEResourceSet) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan tfsdkCTEResourceSetModel
	payload := map[string]interface{}{}

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload["description"] = trimString(plan.Description.String())
	payload["resources"] = plan.Resources

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_resource_set.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Resource Set Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(ctx, plan.ID.ValueString(), URL_CTE_RESOURCE_SET, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_resource_set.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Resource Set on CipherTrust Manager: ",
			"Could not create CTE Resource Set, unexpected error: "+err.Error(),
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
func (r *resourceCTEResourceSet) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state tfsdkCTEResourceSetModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	output, err := r.client.DeleteByID(ctx, state.ID.ValueString(), URL_CTE_RESOURCE_SET)
	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cm_resource_set.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CTE Resource Set",
			"Could not delete CTE Resource Set, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTEResourceSet) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
