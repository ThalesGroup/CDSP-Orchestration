package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource              = &resourceCMUser{}
	_ resource.ResourceWithConfigure = &resourceCMUser{}
)

func NewResourceCMUser() resource.Resource {
	return &resourceCMUser{}
}

type resourceCMUser struct {
	client *Client
}

type tfsdkCMUserModel struct {
	UserID                 types.String `tfsdk:"user_id"`
	Name                   types.String `tfsdk:"full_name"`
	UserName               types.String `tfsdk:"username"`
	Nickname               types.String `tfsdk:"nickname"`
	Email                  types.String `tfsdk:"email"`
	Password               types.String `tfsdk:"password"`
	IsDomainUser           types.Bool   `tfsdk:"is_domain_user"`
	PreventUILogin         types.Bool   `tfsdk:"prevent_ui_login"`
	PasswordChangeRequired types.Bool   `tfsdk:"password_change_required"`
}

func (r *resourceCMUser) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_user"
}

// Schema defines the schema for the resource.
func (r *resourceCMUser) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"user_id": schema.StringAttribute{
				Computed: true,
			},
			"username": schema.StringAttribute{
				Required: true,
			},
			"nickname": schema.StringAttribute{
				Required: true,
			},
			"email": schema.StringAttribute{
				Required: true,
			},
			"full_name": schema.StringAttribute{
				Required: true,
			},
			"password": schema.StringAttribute{
				Required: true,
			},
			"is_domain_user": schema.BoolAttribute{
				Computed: true,
				Default:  booldefault.StaticBool(false),
			},
			"prevent_ui_login": schema.BoolAttribute{
				Computed: true,
				Default:  booldefault.StaticBool(false),
			},
			"password_change_required": schema.BoolAttribute{
				Computed: true,
				Default:  booldefault.StaticBool(false),
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMUser) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Retrieve values from plan
	var plan tfsdkCMUserModel
	var loginFlags UserLoginFlags
	var payload User

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	loginFlags.PreventUILogin = plan.PreventUILogin.ValueBool()

	payload.Email = trimString(plan.Email.String())
	payload.Name = trimString(plan.Name.String())
	payload.Nickname = trimString(plan.Nickname.String())
	payload.UserName = trimString(plan.UserName.String())
	payload.Password = trimString(plan.Password.String())
	payload.IsDomainUser = plan.IsDomainUser.ValueBool()
	payload.LoginFlags = loginFlags
	payload.PasswordChangeRequired = plan.PasswordChangeRequired.ValueBool()

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid data input: User Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, URL_USER_MANAGEMENT, payloadJSON, "user_id")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating user on CipherTrust Manager: ",
			"Could not create user, unexpected error: "+err.Error(),
		)
		return
	}

	plan.UserID = types.StringValue(response)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMUser) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMUser) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMUser) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

func (d *resourceCMUser) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
