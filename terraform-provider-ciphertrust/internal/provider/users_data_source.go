package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &usersDataSource{}
	_ datasource.DataSourceWithConfigure = &usersDataSource{}
)

func NewUsersDataSource() datasource.DataSource {
	return &usersDataSource{}
}

type usersDataSource struct {
	client *Client
}

type usersDataSourceModel struct {
	User []userModel `tfsdk:"users"`
}

type userModel struct {
	UserID   types.String `tfsdk:"user_id"`
	Name     types.String `tfsdk:"name"`
	UserName types.String `tfsdk:"username"`
	Nickname types.String `tfsdk:"nickname"`
	Email    types.String `tfsdk:"email"`
	Password types.String `tfsdk:"password"`
}

type usersFilterModel struct {
	ID types.String `tfsdk:"user_id"`
}

func (d *usersDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_users"
}

func (d *usersDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"users": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"user_id": schema.StringAttribute{
							Computed: true,
						},
						"username": schema.StringAttribute{
							Computed: true,
						},
						"nickname": schema.StringAttribute{
							Computed: true,
						},
						"email": schema.StringAttribute{
							Computed: true,
						},
						"name": schema.StringAttribute{
							Computed: true,
						},
						"password": schema.StringAttribute{
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func (d *usersDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state usersDataSourceModel

	users, err := d.client.GetAll("api/v1/usermgmt/users")
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read Users L1",
			err.Error(),
		)
		return
	}

	for _, user := range users {
		userState := userModel{
			UserID:   types.StringValue(user.UserID),
			Name:     types.StringValue(user.Name),
			Email:    types.StringValue(user.Email),
			Nickname: types.StringValue(user.Nickname),
			UserName: types.StringValue(user.UserName),
			Password: types.StringValue(user.Password),
		}

		state.User = append(state.User, userState)
	}

	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *usersDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	//tflog.Debug(ctx, fmt.Sprintf("Client is: %T", req.ProviderData.(*Client)))

	client, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *hashicups.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}
