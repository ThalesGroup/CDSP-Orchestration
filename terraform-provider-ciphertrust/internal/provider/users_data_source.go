package provider

import (
	"context"
	"fmt"

	"github.com/anugram/ciphertrust-client-go"
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
	client *ciphertrust.Client
}

type usersDataSourceModel struct {
	Coffees []userModel `tfsdk:"users"`
}

// coffeesModel maps coffees schema data.
type userModel struct {
	UserID   types.String `tfsdk:"user_id"`
	Name     types.String `tfsdk:"username"`
	UserName types.String `tfsdk:"nickname"`
	Nickname types.String `tfsdk:"email"`
	Email    types.String `tfsdk:"name"`
	//Ingredients []coffeesIngredientsModel `tfsdk:"ingredients"`
}

// coffeesIngredientsModel maps coffee ingredients data
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
						// "ingredients": schema.ListNestedAttribute{
						// 	Computed: true,
						// 	NestedObject: schema.NestedAttributeObject{
						// 		Attributes: map[string]schema.Attribute{
						// 			"id": schema.Int64Attribute{
						// 				Computed: true,
						// 			},
						// 		},
						// 	},
						// },
					},
				},
			},
		},
	}
}

func (d *usersDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state usersDataSourceModel

	users, err := d.client.GetAll("")
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read HashiCups Coffees",
			err.Error(),
		)
		return
	}

	for _, user := range users {
		coffeeState := userModel{
			UserID:   types.StringValue(user.UserID),
			Name:     types.StringValue(user.Name),
			Email:    types.StringValue(user.Email),
			Nickname: types.StringValue(user.Description),
			UserName: types.StringValue(user.UserName),
		}

		state.Coffees = append(state.Coffees, coffeeState)
	}

	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *usersDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*ciphertrust.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *hashicups.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}
