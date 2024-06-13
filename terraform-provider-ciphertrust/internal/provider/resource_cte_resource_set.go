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
			"type": schema.StringAttribute{
				Optional: true,
			},
			"resources": schema.ListNestedAttribute{
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"directory": schema.StringAttribute{
							Optional: true,
						},
						"file": schema.StringAttribute{
							Optional: true,
						},
						"hdfs": schema.BoolAttribute{
							Optional: true,
						},
						"include_subfolders": schema.BoolAttribute{
							Optional: true,
						},
					},
				},
			},
			"classification_tags": schema.ListNestedAttribute{
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"description": schema.StringAttribute{
							Optional: true,
						},
						"name": schema.StringAttribute{
							Optional: true,
						},
						"attributes": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"data_type": schema.StringAttribute{
										Optional: true,
									},
									"name": schema.StringAttribute{
										Optional: true,
									},
									"operator": schema.StringAttribute{
										Optional: true,
									},
									"value": schema.StringAttribute{
										Optional: true,
									},
								},
							},
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
	var payload CTEResourceSetModelJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Name = trimString(plan.Name.String())
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = trimString(plan.Description.String())
	}
	if plan.Type.ValueString() != "" && plan.Type.ValueString() != types.StringNull().ValueString() {
		payload.Type = trimString(plan.Type.String())
	} else {
		payload.Type = "Directory"
	}

	var tagsJSONArr []ClassificationTagJSON
	for _, tag := range plan.ClassificationTags {
		var tagsJSON ClassificationTagJSON
		if tag.Description.ValueString() != "" && tag.Description.ValueString() != types.StringNull().ValueString() {
			tagsJSON.Description = string(tag.Description.ValueString())
		}
		if tag.Name.ValueString() != "" && tag.Name.ValueString() != types.StringNull().ValueString() {
			tagsJSON.Name = string(tag.Name.ValueString())
		}
		var tagAttributesJSONArr []ClassificationTagAttributesJSON
		for _, atribute := range tag.Attributes {
			var tagAttributesJSON ClassificationTagAttributesJSON
			if atribute.Name.ValueString() != "" && atribute.Name.ValueString() != types.StringNull().ValueString() {
				tagAttributesJSON.Name = string(atribute.Name.ValueString())
			}
			if atribute.DataType.ValueString() != "" && atribute.DataType.ValueString() != types.StringNull().ValueString() {
				tagAttributesJSON.DataType = string(atribute.DataType.ValueString())
			}
			if atribute.Operator.ValueString() != "" && atribute.Operator.ValueString() != types.StringNull().ValueString() {
				tagAttributesJSON.Operator = string(atribute.Operator.ValueString())
			}
			if atribute.Value.ValueString() != "" && atribute.Value.ValueString() != types.StringNull().ValueString() {
				tagAttributesJSON.Value = string(atribute.Value.ValueString())
			}
			tagAttributesJSONArr = append(tagAttributesJSONArr, tagAttributesJSON)
		}
		tagsJSON.Attributes = tagAttributesJSONArr

		tagsJSONArr = append(tagsJSONArr, tagsJSON)
	}
	payload.ClassificationTags = tagsJSONArr

	var resources []CTEResourceJSON
	for _, resource := range plan.Resources {
		var resourceJSON CTEResourceJSON
		if resource.Directory.ValueString() != "" && resource.Directory.ValueString() != types.StringNull().ValueString() {
			resourceJSON.Directory = string(resource.Directory.ValueString())
		}
		if resource.File.ValueString() != "" && resource.File.ValueString() != types.StringNull().ValueString() {
			resourceJSON.File = string(resource.File.ValueString())
		}
		if resource.HDFS.ValueBool() != types.BoolNull().ValueBool() {
			resourceJSON.HDFS = bool(resource.HDFS.ValueBool())
		}
		if resource.IncludeSubfolders.ValueBool() != types.BoolNull().ValueBool() {
			resourceJSON.IncludeSubfolders = bool(resource.IncludeSubfolders.ValueBool())
		}
		resources = append(resources, resourceJSON)
	}
	payload.Resources = resources

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
	var payload CTEResourceSetModelJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Description = trimString(plan.Description.String())

	var tagsJSONArr []ClassificationTagJSON
	for _, tag := range plan.ClassificationTags {
		var tagsJSON ClassificationTagJSON
		if tag.Description.ValueString() != "" && tag.Description.ValueString() != types.StringNull().ValueString() {
			tagsJSON.Description = string(tag.Description.ValueString())
		}
		if tag.Name.ValueString() != "" && tag.Name.ValueString() != types.StringNull().ValueString() {
			tagsJSON.Name = string(tag.Name.ValueString())
		}
		var tagAttributesJSONArr []ClassificationTagAttributesJSON
		for _, atribute := range tag.Attributes {
			var tagAttributesJSON ClassificationTagAttributesJSON
			if atribute.Name.ValueString() != "" && atribute.Name.ValueString() != types.StringNull().ValueString() {
				tagAttributesJSON.Name = string(atribute.Name.ValueString())
			}
			if atribute.DataType.ValueString() != "" && atribute.DataType.ValueString() != types.StringNull().ValueString() {
				tagAttributesJSON.DataType = string(atribute.DataType.ValueString())
			}
			if atribute.Operator.ValueString() != "" && atribute.Operator.ValueString() != types.StringNull().ValueString() {
				tagAttributesJSON.Operator = string(atribute.Operator.ValueString())
			}
			if atribute.Value.ValueString() != "" && atribute.Value.ValueString() != types.StringNull().ValueString() {
				tagAttributesJSON.Value = string(atribute.Value.ValueString())
			}
			tagAttributesJSONArr = append(tagAttributesJSONArr, tagAttributesJSON)
		}
		tagsJSON.Attributes = tagAttributesJSONArr

		tagsJSONArr = append(tagsJSONArr, tagsJSON)
	}
	payload.ClassificationTags = tagsJSONArr

	var resources []CTEResourceJSON
	for _, resource := range plan.Resources {
		var resourceJSON CTEResourceJSON
		if resource.Directory.ValueString() != "" && resource.Directory.ValueString() != types.StringNull().ValueString() {
			resourceJSON.Directory = string(resource.Directory.ValueString())
		}
		if resource.File.ValueString() != "" && resource.File.ValueString() != types.StringNull().ValueString() {
			resourceJSON.File = string(resource.File.ValueString())
		}
		if resource.HDFS.ValueBool() != types.BoolNull().ValueBool() {
			resourceJSON.HDFS = bool(resource.HDFS.ValueBool())
		}
		if resource.IncludeSubfolders.ValueBool() != types.BoolNull().ValueBool() {
			resourceJSON.IncludeSubfolders = bool(resource.IncludeSubfolders.ValueBool())
		}
		resources = append(resources, resourceJSON)
	}
	payload.Resources = resources

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
