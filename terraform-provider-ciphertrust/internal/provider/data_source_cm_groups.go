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
	_ datasource.DataSource              = &dataSourceGroups{}
	_ datasource.DataSourceWithConfigure = &dataSourceGroups{}
)

func NewDataSourceGroups() datasource.DataSource {
	return &dataSourceGroups{}
}

type dataSourceGroups struct {
	client *Client
}

type tfsdkCMGroupsListModel struct {
	Name types.String `tfsdk:"name"`
}

type groupsDataSourceModel struct {
	Filters types.Map                `tfsdk:"filters"`
	Groups  []tfsdkCMGroupsListModel `tfsdk:"groups"`
}

func (d *dataSourceGroups) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_groups_list"
}

func (d *dataSourceGroups) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"groups": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
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

func (d *dataSourceGroups) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, MSG_METHOD_START+"[data_source_cm_groups.go -> Read]["+id+"]")
	var state groupsDataSourceModel

	jsonStr, err := d.client.GetAll(ctx, id, URL_GROUP)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [data_source_cm_groups.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read groups from CM",
			err.Error(),
		)
		return
	}

	groups := []GroupJSON{}

	err = json.Unmarshal([]byte(jsonStr), &groups)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [data_source_cm_groups.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read groups from CM",
			err.Error(),
		)
		return
	}

	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [data_source_cm_groups.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read groups from CM",
			err.Error(),
		)
		return
	}

	for _, group := range groups {
		groupState := tfsdkCMGroupsListModel{
			Name: types.StringValue(group.Name),
		}

		state.Groups = append(state.Groups, groupState)
	}

	tflog.Trace(ctx, MSG_METHOD_END+"[data_source_cm_groups.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceGroups) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
