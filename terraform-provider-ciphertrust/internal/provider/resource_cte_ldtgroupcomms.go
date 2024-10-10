package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceLDTGroupCommSvc{}
	_ resource.ResourceWithConfigure = &resourceLDTGroupCommSvc{}
)

func NewResourceLDTGroupCommSvc() resource.Resource {
	return &resourceLDTGroupCommSvc{}
}

type resourceLDTGroupCommSvc struct {
	client *Client
}

func (r *resourceLDTGroupCommSvc) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_ldtgroupcomms"
}

// Schema defines the schema for the resource.
func (r *resourceLDTGroupCommSvc) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name to uniquely identify the LDT group communication service. This name will be visible on the CipherTrust Manager.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description to identify the LDT group communication service.",
			},
			"client_list": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of identifiers of clients to be associated with the LDT group communication service. This identifier can be the Name, ID (a UUIDv4), URI, or slug of the client.",
			},
			"op_type": schema.StringAttribute{
				Optional:    true,
				Description: "Operation specifying weather to remove or add the provided client list to the GroupComm Service being updated.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{
						"update",
						"add_client_list",
						"delete_client_list"}...),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceLDTGroupCommSvc) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, MSG_METHOD_START+"[resource_cte_ldtgroupcomms.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan tfsdkLDTGroupCommSvc
	var payload jsonLDTGroupCommSvc

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Name = trimString(plan.Name.String())

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = trimString(plan.Description.String())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_ldtgroupcomms.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: LDT Group Communication Service Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, id, URL_LDT_GROUP_COMM_SVC, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_ldtgroupcomms.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating LDT Group Communication Service on CipherTrust Manager: ",
			"Could not create LDT Group Communication Service, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cte_ldtgroupcomms.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceLDTGroupCommSvc) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceLDTGroupCommSvc) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan tfsdkLDTGroupCommSvc
	var payload jsonLDTGroupCommSvc

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.OpType.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		if plan.OpType.ValueString() == "update" {
			if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
				payload.Description = trimString(plan.Description.String())
				payloadJSON, err := json.Marshal(payload)
				if err != nil {
					tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_ldtgroupcomms.go -> Update]["+plan.ID.ValueString()+"]")
					resp.Diagnostics.AddError(
						"Invalid data input: LDT Group Communication Service Update",
						err.Error(),
					)
					return
				}
				response, err := r.client.UpdateData(ctx, plan.ID.ValueString(), URL_CTE_PROCESS_SET, payloadJSON, "id")
				if err != nil {
					tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_ldtgroupcomms.go -> Update]["+plan.ID.ValueString()+"]")
					resp.Diagnostics.AddError(
						"Error creating LDT Group Communication Service on CipherTrust Manager: ",
						"Could not create LDT Group Communication Service, unexpected error: "+err.Error(),
					)
					return
				}
				plan.ID = types.StringValue(response)
			}
		} else {
			if len(plan.ClientList) == 0 {
				resp.Diagnostics.AddError(
					"Client List Required",
					"The 'client_list' attribute must be provided during update.",
				)
				return
			} else {
				if plan.OpType.ValueString() == "add_client_list" {
					var clientsArr []string
					for _, client := range plan.ClientList {
						clientsArr = append(clientsArr, client.ValueString())
					}
					payload.ClientList = clientsArr
					payloadJSON, err := json.Marshal(payload)
					if err != nil {
						tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_ldtgroupcomms.go -> Update]["+plan.ID.ValueString()+"]")
						resp.Diagnostics.AddError(
							"Invalid data input: LDT Group Communication Service Update",
							err.Error(),
						)
						return
					}
					response, err := r.client.PostData(
						ctx,
						plan.ID.ValueString(),
						URL_LDT_GROUP_COMM_SVC+"/"+plan.ID.ValueString()+"/clients",
						payloadJSON,
						"id")
					if err != nil {
						tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_ldtgroupcomms.go -> Update]["+plan.ID.ValueString()+"]")
						resp.Diagnostics.AddError(
							"Error adding clients list to the LDT Group Communication Service on CipherTrust Manager: ",
							"Could not add clients list to the LDT Group Communication Service, unexpected error: "+err.Error(),
						)
						return
					}
					plan.ID = types.StringValue(response)
				}
				if plan.OpType.ValueString() == "delete_client_list" {
					var clientsArr []string
					for _, client := range plan.ClientList {
						clientsArr = append(clientsArr, client.ValueString())
					}
					payload.ClientList = clientsArr
					payloadJSON, err := json.Marshal(payload)
					if err != nil {
						tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_ldtgroupcomms.go -> Update]["+plan.ID.ValueString()+"]")
						resp.Diagnostics.AddError(
							"Invalid data input: LDT Group Communication Service Update",
							err.Error(),
						)
						return
					}
					response, err := r.client.UpdateData(
						ctx,
						plan.ID.ValueString(),
						URL_LDT_GROUP_COMM_SVC+"/"+plan.ID.ValueString()+"/clients/delete",
						payloadJSON,
						"id")
					if err != nil {
						tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cte_ldtgroupcomms.go -> Update]["+plan.ID.ValueString()+"]")
						resp.Diagnostics.AddError(
							"Error deleting clients list from the LDT Group Communication Service on CipherTrust Manager: ",
							"Could not delete clients list from the LDT Group Communication Service, unexpected error: "+err.Error(),
						)
						return
					}
					plan.ID = types.StringValue(response)
				}
			}
		}
	} else {
		resp.Diagnostics.AddError(
			"op_type is a required",
			"The 'op_type' attribute must be provided during update.",
		)
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceLDTGroupCommSvc) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state tfsdkAWSConnectionModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	output, err := r.client.DeleteByID(ctx, state.ID.ValueString(), URL_CTE_PROCESS_SET)
	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cte_ldtgroupcomms.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting LDT Group Communication Service",
			"Could not delete LDT Group Communication Service, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceLDTGroupCommSvc) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
