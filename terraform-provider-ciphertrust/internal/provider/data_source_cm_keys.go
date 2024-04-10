package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &dataSourceKeys{}
	_ datasource.DataSourceWithConfigure = &dataSourceKeys{}
)

func NewDataSourceKeys() datasource.DataSource {
	return &dataSourceKeys{}
}

type dataSourceKeys struct {
	client *Client
}

type keysDataSourceModel struct {
	Keys []tfsdkCMKeyModel `tfsdk:"keys"`
}

func (d *dataSourceKeys) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_keys_list"
}

func (d *dataSourceKeys) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"keys": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed: true,
						},
						"name": schema.StringAttribute{
							Computed: true,
						},
						"usage_mask": schema.Int64Attribute{
							Computed: true,
						},
						"algorithm": schema.StringAttribute{
							Computed: true,
						},
						"size": schema.Int64Attribute{
							Computed: true,
						},
						"uuid": schema.StringAttribute{
							Computed: true,
						},
						"description": schema.StringAttribute{
							Computed: true,
						},
						"activation_date": schema.StringAttribute{
							Computed: true,
						},
						"archive_date": schema.StringAttribute{
							Computed: true,
						},
						"assign_self_as_owner": schema.BoolAttribute{
							Computed: true,
						},
						"cert_type": schema.StringAttribute{
							Computed: true,
						},
						"compromise_date": schema.StringAttribute{
							Computed: true,
						},
						"compromise_occurrence_date": schema.StringAttribute{
							Computed: true,
						},
						"curveid": schema.StringAttribute{
							Computed: true,
						},
						"deactivation_date": schema.StringAttribute{
							Computed: true,
						},
						"default_iv": schema.StringAttribute{
							Computed: true,
						},
						"destroy_date": schema.StringAttribute{
							Computed: true,
						},
						"empty_material": schema.BoolAttribute{
							Computed: true,
						},
						"encoding": schema.StringAttribute{
							Computed: true,
						},
						"format": schema.StringAttribute{
							Computed: true,
						},
						"generate_key_id": schema.BoolAttribute{
							Computed: true,
						},
						"hkdf_create_parameters": schema.SingleNestedAttribute{
							Computed: true,
							Attributes: map[string]schema.Attribute{
								"hash_algorithm": schema.StringAttribute{
									Computed: true,
								},
								"ikm_key_name": schema.StringAttribute{
									Computed: true,
								},
								"info": schema.StringAttribute{
									Computed: true,
								},
								"salt": schema.StringAttribute{
									Computed: true,
								},
							},
						},
						"id_size": schema.Int64Attribute{
							Computed: true,
						},
						"key_id": schema.StringAttribute{
							Computed: true,
						},
						"mac_sign_bytes": schema.StringAttribute{
							Computed: true,
						},
						"mac_sign_key_identifier": schema.StringAttribute{
							Computed: true,
						},
						"mac_sign_key_identifier_type": schema.StringAttribute{
							Computed: true,
						},
						"material": schema.StringAttribute{
							Computed: true,
						},
						"muid": schema.StringAttribute{
							Computed: true,
						},
						"object_type": schema.StringAttribute{
							Computed: true,
						},
						"meta": schema.SingleNestedAttribute{
							Computed: true,
							Attributes: map[string]schema.Attribute{
								"owner_id": schema.StringAttribute{
									Computed: true,
								},
							},
						},
						"padded": schema.BoolAttribute{
							Computed: true,
						},
						"password": schema.StringAttribute{
							Computed: true,
						},
						"process_start_date": schema.StringAttribute{
							Computed: true,
						},
						"protect_stop_date": schema.StringAttribute{
							Computed: true,
						},
						"revocation_reason": schema.StringAttribute{
							Computed: true,
						},
						"revocation_message": schema.StringAttribute{
							Computed: true,
						},
						"rotation_frequency_days": schema.StringAttribute{
							Computed: true,
						},
						"secret_data_encoding": schema.StringAttribute{
							Computed: true,
						},
						"secret_data_link": schema.StringAttribute{
							Computed: true,
						},
						"signing_algo": schema.StringAttribute{
							Computed: true,
						},
						"unexportable": schema.BoolAttribute{
							Computed: true,
						},
						"undeletable": schema.BoolAttribute{
							Computed: true,
						},
						"state": schema.StringAttribute{
							Computed: true,
						},
						"wrap_key_id_type": schema.StringAttribute{
							Computed: true,
						},
						"wrap_key_name": schema.StringAttribute{
							Computed: true,
						},
						"wrap_public_key": schema.StringAttribute{
							Computed: true,
						},
						"wrap_public_key_padding": schema.StringAttribute{
							Computed: true,
						},
						"wrapping_encryption_algo": schema.StringAttribute{
							Computed: true,
						},
						"wrapping_hash_algo": schema.StringAttribute{
							Computed: true,
						},
						"wrapping_method": schema.StringAttribute{
							Computed: true,
						},
						"xts": schema.BoolAttribute{
							Computed: true,
						},
						"aliases": schema.ListNestedAttribute{
							Computed: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"alias": schema.StringAttribute{
										Required: true,
									},
									"index": schema.Int64Attribute{
										Required: true,
									},
									"type": schema.StringAttribute{
										Required: true,
									},
								},
							},
						},
						"public_key_parameters": schema.SingleNestedAttribute{
							Computed: true,
							Attributes: map[string]schema.Attribute{
								"activation_date": schema.StringAttribute{
									Computed: true,
								},
								"archive_date": schema.StringAttribute{
									Computed: true,
								},
								"deactivation_date": schema.StringAttribute{
									Computed: true,
								},
								"name": schema.StringAttribute{
									Computed: true,
								},
								"state": schema.StringAttribute{
									Computed: true,
								},
								"undeletable": schema.BoolAttribute{
									Computed: true,
								},
								"unexportable": schema.BoolAttribute{
									Computed: true,
								},
								"usage_mask": schema.Int64Attribute{
									Computed: true,
								},
								"aliases": schema.ListNestedAttribute{
									Computed: true,
									NestedObject: schema.NestedAttributeObject{
										Attributes: map[string]schema.Attribute{
											"alias": schema.StringAttribute{
												Required: true,
											},
											"index": schema.Int64Attribute{
												Required: true,
											},
											"type": schema.StringAttribute{
												Required: true,
											},
										},
									},
								},
							},
						},
						"wrap_hkdf": schema.SingleNestedAttribute{
							Computed: true,
							Attributes: map[string]schema.Attribute{
								"hash_algorithm": schema.StringAttribute{
									Computed: true,
								},
								"okm_len": schema.Int64Attribute{
									Computed: true,
								},
								"info": schema.StringAttribute{
									Computed: true,
								},
								"salt": schema.StringAttribute{
									Computed: true,
								},
							},
						},
						"wrap_pbe": schema.SingleNestedAttribute{
							Computed: true,
							Attributes: map[string]schema.Attribute{
								"dklen": schema.Int64Attribute{
									Computed: true,
								},
								"hash_algorithm": schema.StringAttribute{
									Computed: true,
								},
								"salt": schema.StringAttribute{
									Computed: true,
								},
								"iteration": schema.Int64Attribute{
									Computed: true,
								},
								"password": schema.StringAttribute{
									Computed: true,
								},
								"password_identifier": schema.StringAttribute{
									Computed: true,
								},
								"password_identifier_type": schema.StringAttribute{
									Computed: true,
								},
								"purpose": schema.StringAttribute{
									Computed: true,
								},
							},
						},
						"wrap_rsaaes": schema.SingleNestedAttribute{
							Computed: true,
							Attributes: map[string]schema.Attribute{
								"aes_key_size": schema.Int64Attribute{
									Computed: true,
								},
								"padding": schema.StringAttribute{
									Computed: true,
								},
							},
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceKeys) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state keysDataSourceModel

	jsonStr, err := d.client.GetAll(URL_KEY_MANAGEMENT)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to read Keys from CM",
			err.Error(),
		)
		return
	}

	var data []map[string]any

	err = json.Unmarshal([]byte(jsonStr), &data)

	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to read keys from CM",
			err.Error(),
		)
		return
	}

	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to read keys from CM",
			err.Error(),
		)
		return
	}

	for _, key := range data {
		keyState := tfsdkCMKeyModel{}
		if key["name"] != nil {
			keyState.Name = types.StringValue(key["name"].(string))
		}
		if key["id"] != nil {
			keyState.ID = types.StringValue(key["id"].(string))
		}
		if key["uuid"] != nil {
			keyState.UUID = types.StringValue(key["uuid"].(string))
		}
		if key["usageMask"] != nil {
			keyState.UsageMask = types.Int64Value(int64(key["usageMask"].(float64)))
		}
		if key["size"] != nil {
			keyState.Size = types.Int64Value(int64(key["size"].(float64)))
		}
		if key["algorithm"] != nil {
			keyState.Algorithm = types.StringValue(key["algorithm"].(string))
		}
		if key["unexportable"] != nil {
			keyState.Exportable = types.BoolValue(key["unexportable"].(bool))
		}
		if key["undeletable"] != nil {
			keyState.Deletable = types.BoolValue(key["undeletable"].(bool))
		}
		state.Keys = append(state.Keys, keyState)
	}

	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceKeys) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

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
