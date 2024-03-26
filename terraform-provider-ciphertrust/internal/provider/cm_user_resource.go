package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource              = &cmUserResource{}
	_ resource.ResourceWithConfigure = &cmUserResource{}
)

// NewOrderResource is a helper function to simplify the provider implementation.
func NewCMUserResource() resource.Resource {
	return &cmUserResource{}
}

// orderResource is the resource implementation.
type cmUserResource struct {
	client *Client
}

type cmUsersListResourceModel struct {
	User []cmUserModel `tfsdk:"users"`
}

type cmUserModel struct {
	UserID   types.String `tfsdk:"user_id"`
	Name     types.String `tfsdk:"name"`
	UserName types.String `tfsdk:"username"`
	Nickname types.String `tfsdk:"nickname"`
	Email    types.String `tfsdk:"email"`
	Password types.String `tfsdk:"password"`
}

type cmUserFilterModel struct {
	ID types.String `tfsdk:"user_id"`
}

// Metadata returns the resource type name.
func (r *cmUserResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_user"
}

// Schema defines the schema for the resource.
func (r *cmUserResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"user_id": schema.StringAttribute{
				Optional: true,
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
			"name": schema.StringAttribute{
				Required: true,
			},
			"password": schema.StringAttribute{
				Required: true,
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *cmUserResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Retrieve values from plan
	var plan cmUserModel
	var createUserData User

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	createUserData.Email = plan.UserID.String()
	createUserData.Name = plan.Name.String()
	createUserData.Nickname = plan.Nickname.String()
	createUserData.UserName = plan.UserName.String()
	createUserData.Password = plan.Password.String()

	responseJSON, err := r.client.SaveUser(ctx, "api/v1/usermgmt/users", createUserData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating user: ",
			"Could not create user, unexpected error: "+err.Error(),
		)
		return
	}

	plan.UserID = types.StringValue(responseJSON.UserID)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *cmUserResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *cmUserResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *cmUserResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

func (d *cmUserResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
