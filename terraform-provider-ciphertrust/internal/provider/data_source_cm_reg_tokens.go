package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &dataSourceRegTokens{}
	_ datasource.DataSourceWithConfigure = &dataSourceRegTokens{}
)

func NewDataSourceRegTokens() datasource.DataSource {
	return &dataSourceRegTokens{}
}

type dataSourceRegTokens struct {
	client *Client
}

type RegTokensDataSourceModel struct {
	Filters types.Map                   `tfsdk:"filters"`
	Tokens  []tfsdkCMRegTokensListModel `tfsdk:"tokens"`
}

func (d *dataSourceRegTokens) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_tokens_list"
}

func (d *dataSourceRegTokens) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"tokens": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed: true,
						},
						"uri": schema.StringAttribute{
							Computed: true,
						},
						"account": schema.StringAttribute{
							Computed: true,
						},
						"application": schema.StringAttribute{
							Computed: true,
						},
						"dev_account": schema.StringAttribute{
							Computed: true,
						},
						"created_at": schema.StringAttribute{
							Computed: true,
						},
						"updated_at": schema.StringAttribute{
							Computed: true,
						},
						"token": schema.StringAttribute{
							Computed: true,
						},
						"valid_until": schema.StringAttribute{
							Computed: true,
						},
						"max_clients": schema.Int64Attribute{
							Computed: true,
						},
						"clients_registered": schema.Int64Attribute{
							Computed: true,
						},
						"ca_id": schema.StringAttribute{
							Computed: true,
						},
						"name_prefix": schema.StringAttribute{
							Computed: true,
						},
					},
				},
			},
			"filters": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
		},
	}
}

func (d *dataSourceRegTokens) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, MSG_METHOD_START+"[data_source_cm_reg_tokens.go -> Read]["+id+"]")
	var state RegTokensDataSourceModel
	req.Config.Get(ctx, &state)
	var kvs []string
	for k, v := range state.Filters.Elements() {
		kv := fmt.Sprintf("%s=%s&", k, v.(types.String).ValueString())
		kvs = append(kvs, kv)
	}

	jsonStr, err := d.client.GetAll(
		ctx,
		id,
		URL_REG_TOKEN+"/?"+strings.Join(kvs, "")+"skip=0&limit=10")

	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [data_source_cm_reg_tokens.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read reg tokens from CM",
			err.Error(),
		)
		return
	}

	tokens := []jsonCMRegTokensListModel{}

	err = json.Unmarshal([]byte(jsonStr), &tokens)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [data_source_cm_reg_tokens.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read reg tokens from CM",
			err.Error(),
		)
		return
	}

	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [data_source_cm_reg_tokens.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read reg tokens from CM",
			err.Error(),
		)
		return
	}

	for _, token := range tokens {
		tokenState := tfsdkCMRegTokensListModel{
			ID:                types.StringValue(token.ID),
			URI:               types.StringValue(token.URI),
			Account:           types.StringValue(token.Account),
			Application:       types.StringValue(token.Application),
			DevAccount:        types.StringValue(token.DevAccount),
			CreatedAt:         types.StringValue(token.CreatedAt),
			UpdatedAt:         types.StringValue(token.UpdatedAt),
			Token:             types.StringValue(token.Token),
			ValidUntil:        types.StringValue(token.ValidUntil),
			MaxClients:        types.Int64Value(token.MaxClients),
			ClientsRegistered: types.Int64Value(token.ClientsRegistered),
			CAID:              types.StringValue(token.CAID),
			NamePrefix:        types.StringValue(token.NamePrefix),
		}

		state.Tokens = append(state.Tokens, tokenState)
	}

	tflog.Trace(ctx, MSG_METHOD_END+"[data_source_cm_reg_tokens.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceRegTokens) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
