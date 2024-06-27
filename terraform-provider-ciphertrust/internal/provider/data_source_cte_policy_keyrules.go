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
	_ datasource.DataSource              = &dataSourceCTEPolicyKeyRule{}
	_ datasource.DataSourceWithConfigure = &dataSourceCTEPolicyKeyRule{}
)

func NewDataSourceCTEPolicyKeyRule() datasource.DataSource {
	return &dataSourceCTEPolicyKeyRule{}
}

type dataSourceCTEPolicyKeyRule struct {
	client *Client
}

type CTEPolicyKeyRuleDataSourceModel struct {
	PolicyID types.String                         `tfsdk:"policy"`
	Rules    []tfsdkCTEPolicyDataTxRulesListModel `tfsdk:"rules"`
}

func (d *dataSourceCTEPolicyKeyRule) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_policy_key_rules"
}

func (d *dataSourceCTEPolicyKeyRule) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"policy": schema.StringAttribute{
				Optional: true,
			},
			"rules": schema.ListNestedAttribute{
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
						"policy_id": schema.StringAttribute{
							Computed: true,
						},
						"order_number": schema.Int64Attribute{
							Computed: true,
						},
						"key_id": schema.StringAttribute{
							Computed: true,
						},
						"new_key_rule": schema.BoolAttribute{
							Computed: true,
						},
						"resource_set_id": schema.StringAttribute{
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceCTEPolicyKeyRule) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, MSG_METHOD_START+"[data_source_cte_policy_keyrules.go -> Read]["+id+"]")
	var state CTEPolicyKeyRuleDataSourceModel
	req.Config.Get(ctx, &state)
	tflog.Info(ctx, "AnuragJain =====> "+state.PolicyID.ValueString())

	jsonStr, err := d.client.GetAll(
		ctx,
		id,
		URL_CTE_POLICY+"/"+state.PolicyID.ValueString()+"/keyrules")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [data_source_cte_policy_keyrules.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy Key Rules from CM",
			err.Error(),
		)
		return
	}

	rules := []CTEPolicyDataTxRulesJSON{}

	err = json.Unmarshal([]byte(jsonStr), &rules)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [data_source_cte_policy_keyrules.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy Key Rules from CM",
			err.Error(),
		)
		return
	}

	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [data_source_cte_policy_keyrules.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy Key Rules from CM",
			err.Error(),
		)
		return
	}

	for _, rule := range rules {
		keyRule := tfsdkCTEPolicyDataTxRulesListModel{}
		keyRule.ID = types.StringValue(rule.ID)
		keyRule.URI = types.StringValue(rule.URI)
		keyRule.Account = types.StringValue(rule.Account)
		keyRule.Application = types.StringValue(rule.Application)
		keyRule.DevAccount = types.StringValue(rule.DevAccount)
		keyRule.CreateAt = types.StringValue(rule.CreatedAt)
		keyRule.UpdatedAt = types.StringValue(rule.UpdatedAt)
		keyRule.PolicyID = types.StringValue(rule.PolicyID)
		keyRule.OrderNumber = types.Int64Value(rule.OrderNumber)
		keyRule.KeyID = types.StringValue(rule.KeyID)
		keyRule.NewKeyRule = types.BoolValue(rule.NewKeyRule)
		keyRule.ResourceSetID = types.StringValue(rule.ResourceSetID)

		state.Rules = append(state.Rules, keyRule)
	}

	tflog.Trace(ctx, MSG_METHOD_END+"[data_source_cte_policy_keyrules.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceCTEPolicyKeyRule) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
