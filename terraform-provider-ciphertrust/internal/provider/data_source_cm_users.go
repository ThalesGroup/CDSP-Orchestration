package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &dataSourceUsers{}
	_ datasource.DataSourceWithConfigure = &dataSourceUsers{}
)

func NewDataSourceUsers() datasource.DataSource {
	return &dataSourceUsers{}
}

type dataSourceUsers struct {
	client *Client
}

type usersDataSourceModel struct {
	User []tfsdkCMUserModel `tfsdk:"users"`
}

func (d *dataSourceUsers) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_users_list"
}

func (d *dataSourceUsers) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
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
						"full_name": schema.StringAttribute{
							Computed: true,
						},
						"password": schema.StringAttribute{
							Computed: true,
						},
						"is_domain_user": schema.BoolAttribute{
							Computed: true,
						},
						"prevent_ui_login": schema.BoolAttribute{
							Computed: true,
						},
						"password_change_required": schema.BoolAttribute{
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceUsers) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, MSG_METHOD_START+"[data_source_cm_users.go -> Read]["+id+"]")
	var state usersDataSourceModel

	jsonStr, err := d.client.GetAll(ctx, id, URL_USER_MANAGEMENT)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [data_source_cm_users.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read users from CM",
			err.Error(),
		)
		return
	}

	users := []UserJSON{}

	err = json.Unmarshal([]byte(jsonStr), &users)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [data_source_cm_users.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read users from CM",
			err.Error(),
		)
		return
	}

	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [data_source_cm_users.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read users from CM",
			err.Error(),
		)
		return
	}

	for _, user := range users {
		userState := tfsdkCMUserModel{
			UserID:                 types.StringValue(user.UserID),
			Name:                   types.StringValue(user.Name),
			Email:                  types.StringValue(user.Email),
			Nickname:               types.StringValue(user.Nickname),
			UserName:               types.StringValue(user.UserName),
			Password:               types.StringValue(user.Password),
			IsDomainUser:           types.BoolValue(user.IsDomainUser),
			PasswordChangeRequired: types.BoolValue(user.PasswordChangeRequired),
		}

		state.User = append(state.User, userState)
	}

	tflog.Trace(ctx, MSG_METHOD_END+"[data_source_cm_users.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceUsers) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *CipherTrust.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}
