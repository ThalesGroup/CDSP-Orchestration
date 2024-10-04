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

func NewResourceCCKMAWSConnection() resource.Resource {
	return &resourceCCKMAWSConnection{}
}

type resourceCCKMAWSConnection struct {
	client *Client
}

func (r *resourceCCKMAWSConnection) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_connection"
}

// Schema defines the schema for the resource.
func (r *resourceCCKMAWSConnection) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
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
				Description: "Unique connection name",
			},
			"access_key_id": schema.StringAttribute{
				Optional:    true,
				Description: "Key ID of the AWS user",
			},
			"assume_role_arn": schema.StringAttribute{
				Optional:    true,
				Description: "AWS IAM role ARN",
			},
			"assume_role_external_id": schema.StringAttribute{
				Optional:    true,
				Description: "Specify AWS Role external ID",
			},
			"aws_region": schema.StringAttribute{
				Optional: true,
				Description: "AWS region. only used when aws_sts_regional_endpoints is equal to regional otherwise, it takes default values according to Cloud Name given." +
					"Default values are: \n" +
					"for aws, default region will be \"us-east-1\" \n" +
					"for aws-us-gov, default region will be \"us-gov-east-1\" \n" +
					"for aws-cn, default region will be \"cn-north-1\"",
			},
			"aws_sts_regional_endpoints": schema.StringAttribute{
				Optional: true,
				Description: "By default, AWS Security Token Service (AWS STS) is available as a global service, and all AWS STS requests go to a single endpoint at https://sts.amazonaws.com. Global requests map to the US East (N. Virginia) Region. AWS recommends using Regional AWS STS endpoints instead of the global endpoint to reduce latency, build in redundancy, and increase session token validity. valid values are: \n" +
					"legacy (default): Uses the global AWS STS endpoint, sts.amazonaws.com \n" +
					"regional: The SDK or tool always uses the AWS STS endpoint for the currently configured Region. \n",
			},
			"cloud_name": schema.StringAttribute{
				Optional: true,
				Description: "Name of the cloud. Options are: \n" +
					"aws (default) \n" +
					"aws-us-gov \n" +
					"aws-cn",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description about the connection",
			},
			"iam_role_anywhere": schema.ListNestedAttribute{
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"anywhere_role_arn": schema.StringAttribute{
							Required:    true,
							Description: "Specify AWS IAM Anywhere Role ARN",
						},
						"certificate": schema.StringAttribute{
							Required:    true,
							Description: "Upload the external certificate for AWS IAM Anywhere Cloud connections. This option is used when \"role_anywhere\" is set to \"true\".",
						},
						"profile_arn": schema.StringAttribute{
							Required:    true,
							Description: "Specify AWS IAM Anywhere Profile ARN",
						},
						"trust_anchor_arn": schema.StringAttribute{
							Required:    true,
							Description: "Specify AWS IAM Anywhere Trust Anchor ARN",
						},
						"private_key": schema.StringAttribute{
							Optional:    true,
							Description: "The private key associated with the certificate",
						},
					},
				},
			},
			"is_role_anywhere": schema.BoolAttribute{
				Optional:    true,
				Description: "Set the parameter to true to create connections of type AWS IAM Anywhere with temporary credentials.",
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Labels are key/value pairs used to group resources. They are based on Kubernetes Labels, see https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/.",
			},
			"meta": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Optional end-user or service data stored with the connection.",
			},
			"products": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Array of the CipherTrust products associated with the connection",
			},
			"secret_access_key": schema.StringAttribute{
				Optional:    true,
				Description: "Secret associated with the access key ID of the AWS user",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCCKMAWSConnection) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, MSG_METHOD_START+"[resource_aws_connection.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan tfsdkAWSConnectionModel
	var payload jsonAWSConnectionModel

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Name = trimString(plan.Name.String())

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = trimString(plan.Description.String())
	}
	if plan.AccessKeyID.ValueString() != "" && plan.AccessKeyID.ValueString() != types.StringNull().ValueString() {
		payload.AccessKeyID = trimString(plan.AccessKeyID.String())
	}
	if plan.AssumeRoleARN.ValueString() != "" && plan.AssumeRoleARN.ValueString() != types.StringNull().ValueString() {
		payload.AssumeRoleARN = trimString(plan.AssumeRoleARN.String())
	}
	if plan.AssumeRoleExternalID.ValueString() != "" && plan.AssumeRoleExternalID.ValueString() != types.StringNull().ValueString() {
		payload.AssumeRoleExternalID = trimString(plan.AssumeRoleExternalID.String())
	}
	if plan.AWSRegion.ValueString() != "" && plan.AWSRegion.ValueString() != types.StringNull().ValueString() {
		payload.AWSRegion = trimString(plan.AWSRegion.String())
	}
	if plan.AWSSTSRegionalEndpoints.ValueString() != "" && plan.AWSSTSRegionalEndpoints.ValueString() != types.StringNull().ValueString() {
		payload.AWSSTSRegionalEndpoints = trimString(plan.AWSSTSRegionalEndpoints.String())
	}
	if plan.CloudName.ValueString() != "" && plan.CloudName.ValueString() != types.StringNull().ValueString() {
		payload.CloudName = trimString(plan.CloudName.String())
	}

	var varIAMRoleAnywhere IAMRoleAnywhereJSON
	if (TFSDK_IAMRoleAnywhere{} != plan.IAMRoleAnywhere) {
		if plan.IAMRoleAnywhere.AnywhereRoleARN.ValueString() != "" && plan.IAMRoleAnywhere.AnywhereRoleARN.ValueString() != types.StringNull().ValueString() {
			varIAMRoleAnywhere.AnywhereRoleARN = plan.IAMRoleAnywhere.AnywhereRoleARN.ValueString()
		}
		if plan.IAMRoleAnywhere.Certificate.ValueString() != "" && plan.IAMRoleAnywhere.Certificate.ValueString() != types.StringNull().ValueString() {
			varIAMRoleAnywhere.Certificate = plan.IAMRoleAnywhere.Certificate.ValueString()
		}
		if plan.IAMRoleAnywhere.ProfileARN.ValueString() != "" && plan.IAMRoleAnywhere.ProfileARN.ValueString() != types.StringNull().ValueString() {
			varIAMRoleAnywhere.ProfileARN = plan.IAMRoleAnywhere.ProfileARN.ValueString()
		}
		if plan.IAMRoleAnywhere.TrustAnchorARN.ValueString() != "" && plan.IAMRoleAnywhere.TrustAnchorARN.ValueString() != types.StringNull().ValueString() {
			varIAMRoleAnywhere.TrustAnchorARN = plan.IAMRoleAnywhere.TrustAnchorARN.ValueString()
		}
		if plan.IAMRoleAnywhere.PrivateKey.ValueString() != "" && plan.IAMRoleAnywhere.PrivateKey.ValueString() != types.StringNull().ValueString() {
			varIAMRoleAnywhere.PrivateKey = plan.IAMRoleAnywhere.PrivateKey.ValueString()
		}
		payload.IAMRoleAnywhere = &varIAMRoleAnywhere
	}

	if plan.IsRoleAnywhere.ValueBool() != types.BoolNull().ValueBool() {
		payload.IsRoleAnywhere = plan.IsRoleAnywhere.ValueBool()
	}

	if plan.SecretAccessKey.ValueString() != "" && plan.SecretAccessKey.ValueString() != types.StringNull().ValueString() {
		payload.SecretAccessKey = trimString(plan.SecretAccessKey.String())
	}

	// Add labels to payload
	labelsPayload := make(map[string]interface{})
	for k, v := range plan.Labels.Elements() {
		labelsPayload[k] = v.(types.String).ValueString()
	}
	payload.Labels = labelsPayload

	// Add labels to payload
	metaPayload := make(map[string]interface{})
	for k, v := range plan.Meta.Elements() {
		metaPayload[k] = v.(types.String).ValueString()
	}
	payload.Meta = metaPayload

	var productsArr []string
	for _, product := range plan.Products {
		productsArr = append(productsArr, product.ValueString())
	}
	payload.Products = productsArr

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_aws_connection.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Process Set Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, id, URL_AWS_CONNECTION, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_aws_connection.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Process Set on CipherTrust Manager: ",
			"Could not create CTE Process Set, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, MSG_METHOD_END+"[resource_aws_connection.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCCKMAWSConnection) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCCKMAWSConnection) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan tfsdkAWSConnectionModel
	var payload jsonAWSConnectionModel

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = trimString(plan.Description.String())
	}
	if plan.AccessKeyID.ValueString() != "" && plan.AccessKeyID.ValueString() != types.StringNull().ValueString() {
		payload.AccessKeyID = trimString(plan.AccessKeyID.String())
	}
	if plan.AssumeRoleARN.ValueString() != "" && plan.AssumeRoleARN.ValueString() != types.StringNull().ValueString() {
		payload.AssumeRoleARN = trimString(plan.AssumeRoleARN.String())
	}
	if plan.AssumeRoleExternalID.ValueString() != "" && plan.AssumeRoleExternalID.ValueString() != types.StringNull().ValueString() {
		payload.AssumeRoleExternalID = trimString(plan.AssumeRoleExternalID.String())
	}
	if plan.AWSRegion.ValueString() != "" && plan.AWSRegion.ValueString() != types.StringNull().ValueString() {
		payload.AWSRegion = trimString(plan.AWSRegion.String())
	}
	if plan.AWSSTSRegionalEndpoints.ValueString() != "" && plan.AWSSTSRegionalEndpoints.ValueString() != types.StringNull().ValueString() {
		payload.AWSSTSRegionalEndpoints = trimString(plan.AWSSTSRegionalEndpoints.String())
	}
	if plan.CloudName.ValueString() != "" && plan.CloudName.ValueString() != types.StringNull().ValueString() {
		payload.CloudName = trimString(plan.CloudName.String())
	}

	var varIAMRoleAnywhere IAMRoleAnywhereJSON
	if (TFSDK_IAMRoleAnywhere{} != plan.IAMRoleAnywhere) {
		if plan.IAMRoleAnywhere.AnywhereRoleARN.ValueString() != "" && plan.IAMRoleAnywhere.AnywhereRoleARN.ValueString() != types.StringNull().ValueString() {
			varIAMRoleAnywhere.AnywhereRoleARN = plan.IAMRoleAnywhere.AnywhereRoleARN.ValueString()
		}
		if plan.IAMRoleAnywhere.Certificate.ValueString() != "" && plan.IAMRoleAnywhere.Certificate.ValueString() != types.StringNull().ValueString() {
			varIAMRoleAnywhere.Certificate = plan.IAMRoleAnywhere.Certificate.ValueString()
		}
		if plan.IAMRoleAnywhere.ProfileARN.ValueString() != "" && plan.IAMRoleAnywhere.ProfileARN.ValueString() != types.StringNull().ValueString() {
			varIAMRoleAnywhere.ProfileARN = plan.IAMRoleAnywhere.ProfileARN.ValueString()
		}
		if plan.IAMRoleAnywhere.TrustAnchorARN.ValueString() != "" && plan.IAMRoleAnywhere.TrustAnchorARN.ValueString() != types.StringNull().ValueString() {
			varIAMRoleAnywhere.TrustAnchorARN = plan.IAMRoleAnywhere.TrustAnchorARN.ValueString()
		}
		if plan.IAMRoleAnywhere.PrivateKey.ValueString() != "" && plan.IAMRoleAnywhere.PrivateKey.ValueString() != types.StringNull().ValueString() {
			varIAMRoleAnywhere.PrivateKey = plan.IAMRoleAnywhere.PrivateKey.ValueString()
		}
		payload.IAMRoleAnywhere = &varIAMRoleAnywhere
	}

	if plan.SecretAccessKey.ValueString() != "" && plan.SecretAccessKey.ValueString() != types.StringNull().ValueString() {
		payload.SecretAccessKey = trimString(plan.SecretAccessKey.String())
	}

	// Add labels to payload
	labelsPayload := make(map[string]interface{})
	for k, v := range plan.Labels.Elements() {
		labelsPayload[k] = v.(types.String).ValueString()
	}
	payload.Labels = labelsPayload

	// Add labels to payload
	metaPayload := make(map[string]interface{})
	for k, v := range plan.Meta.Elements() {
		metaPayload[k] = v.(types.String).ValueString()
	}
	payload.Meta = metaPayload

	var productsArr []string
	for _, product := range plan.Products {
		productsArr = append(productsArr, product.ValueString())
	}
	payload.Products = productsArr

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_aws_connection.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Process Set Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(ctx, plan.ID.ValueString(), URL_CTE_PROCESS_SET, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_aws_connection.go -> Update]["+plan.ID.ValueString()+"]")
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
func (r *resourceCCKMAWSConnection) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state tfsdkAWSConnectionModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	output, err := r.client.DeleteByID(ctx, state.ID.ValueString(), URL_CTE_PROCESS_SET)
	tflog.Trace(ctx, MSG_METHOD_END+"[resource_aws_connection.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CTE Process Set",
			"Could not delete CTE Process Set, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCCKMAWSConnection) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
