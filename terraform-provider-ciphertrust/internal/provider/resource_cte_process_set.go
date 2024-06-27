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
	_ resource.Resource              = &resourceCTEProcessSet{}
	_ resource.ResourceWithConfigure = &resourceCTEProcessSet{}
)

func NewResourceCTEProcessSet() resource.Resource {
	return &resourceCTEProcessSet{}
}

type resourceCTEProcessSet struct {
	client *Client
}

func (r *resourceCTEProcessSet) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_process_set"
}

// Schema defines the schema for the resource.
func (r *resourceCTEProcessSet) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
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
			"processes": schema.ListNestedAttribute{
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"directory": schema.StringAttribute{
							Optional: true,
						},
						"file": schema.StringAttribute{
							Optional: true,
						},
						"resource_set_id": schema.StringAttribute{
							Optional: true,
						},
						"signature": schema.StringAttribute{
							Optional: true,
						},
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEProcessSet) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, MSG_METHOD_START+"[resource_cm_process_set.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan tfsdkCTEProcessSetModel
	var payload CTEProcessSetModelJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Name = trimString(plan.Name.String())
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = trimString(plan.Description.String())
	}
	var processes []CTEProcessJSON
	for _, process := range plan.Processes {
		var processJSON CTEProcessJSON
		if process.Directory.ValueString() != "" && process.Directory.ValueString() != types.StringNull().ValueString() {
			processJSON.Directory = string(process.Directory.ValueString())
		}
		if process.File.ValueString() != "" && process.File.ValueString() != types.StringNull().ValueString() {
			processJSON.File = string(process.File.ValueString())
		}
		if process.ResourceSetId.ValueString() != "" && process.ResourceSetId.ValueString() != types.StringNull().ValueString() {
			processJSON.ResourceSetId = string(process.ResourceSetId.ValueString())
		}
		if process.Signature.ValueString() != "" && process.Signature.ValueString() != types.StringNull().ValueString() {
			processJSON.Signature = string(process.Signature.ValueString())
		}
		processes = append(processes, processJSON)
	}
	payload.Processes = processes

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_process_set.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Process Set Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, id, URL_CTE_PROCESS_SET, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_process_set.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Process Set on CipherTrust Manager: ",
			"Could not create CTE Process Set, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cm_process_set.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEProcessSet) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEProcessSet) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan tfsdkCTEProcessSetModel
	var payload CTEProcessSetModelJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = trimString(plan.Description.String())
	}
	var processes []CTEProcessJSON
	for _, process := range plan.Processes {
		var processJSON CTEProcessJSON
		if process.Directory.ValueString() != "" && process.Directory.ValueString() != types.StringNull().ValueString() {
			processJSON.Directory = string(process.Directory.ValueString())
		}
		if process.File.ValueString() != "" && process.File.ValueString() != types.StringNull().ValueString() {
			processJSON.File = string(process.File.ValueString())
		}
		if process.ResourceSetId.ValueString() != "" && process.ResourceSetId.ValueString() != types.StringNull().ValueString() {
			processJSON.ResourceSetId = string(process.ResourceSetId.ValueString())
		}
		if process.Signature.ValueString() != "" && process.Signature.ValueString() != types.StringNull().ValueString() {
			processJSON.Signature = string(process.Signature.ValueString())
		}
		processes = append(processes, processJSON)
	}
	payload.Processes = processes

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_process_set.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Process Set Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(ctx, plan.ID.ValueString(), URL_CTE_PROCESS_SET, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_process_set.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Process Set on CipherTrust Manager: ",
			"Could not create CTE Process Set, unexpected error: "+err.Error(),
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
func (r *resourceCTEProcessSet) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state tfsdkCTEProcessSetModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	output, err := r.client.DeleteByID(ctx, state.ID.ValueString(), URL_CTE_PROCESS_SET)
	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cm_process_set.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CTE Process Set",
			"Could not delete CTE Process Set, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTEProcessSet) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
