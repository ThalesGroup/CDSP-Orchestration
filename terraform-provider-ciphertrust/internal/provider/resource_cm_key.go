package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource              = &resourceCMKey{}
	_ resource.ResourceWithConfigure = &resourceCMKey{}
)

func NewResourceCMKey() resource.Resource {
	return &resourceCMKey{}
}

type resourceCMKey struct {
	client *Client
}

type HKDFParameters struct {
	HashAlgorithm types.String `tfsdk:"hash_algorithm"`
	IKMKeyName    types.String `tfsdk:"ikm_key_name"`
	Info          types.String `tfsdk:"info"`
	Salt          types.String `tfsdk:"salt"`
}

type KeyMetadata struct {
	OwnerId types.String `tfsdk:"owner_id"`
}

type KeyAlias struct {
	Alias types.String `tfsdk:"alias"`
	Index types.Int64  `tfsdk:"index"`
	Type  types.String `tfsdk:"type"`
}

type PublicKeyParameters struct {
	ActivationDate   types.String `tfsdk:"activation_date"`
	Aliases          []KeyAlias   `tfsdk:"aliases"`
	ArchiveDate      types.String `tfsdk:"archive_date"`
	DeactivationDate types.String `tfsdk:"deactivation_date"`
	Name             types.String `tfsdk:"name"`
	State            types.String `tfsdk:"state"`
	Deletable        types.Bool   `tfsdk:"undeletable"`
	Exportable       types.Bool   `tfsdk:"unexportable"`
	UsageMask        types.Int64  `tfsdk:"usage_mask"`
}

type WrapHKDF struct {
	HashAlgorithm types.String `tfsdk:"hash_algorithm"`
	Info          types.String `tfsdk:"info"`
	OKMLen        types.Int64  `tfsdk:"okm_len"`
	Salt          types.String `tfsdk:"salt"`
}

type WrapPBE struct {
	DKLen                  types.Int64  `tfsdk:"dklen"`
	HashAlgorithm          types.String `tfsdk:"hash_algorithm"`
	Iteration              types.Int64  `tfsdk:"iteration"`
	Password               types.String `tfsdk:"password"`
	PasswordIdentifier     types.String `tfsdk:"password_identifier"`
	PasswordIdentifierType types.String `tfsdk:"password_identifier_type"`
	Purpose                types.String `tfsdk:"purpose"`
	Salt                   types.String `tfsdk:"salt"`
}

type WrapRSAAES struct {
	AESKeySize types.Int64  `tfsdk:"aes_key_size"`
	Padding    types.String `tfsdk:"padding"`
}

type tfsdkCMKeyModel struct {
	ID                       types.String        `tfsdk:"id"`
	ActivationDate           types.String        `tfsdk:"activation_date"`
	Algorithm                types.String        `tfsdk:"algorithm"`
	ArchiveDate              types.String        `tfsdk:"archive_date"`
	AssignSelfAsOwner        types.Bool          `tfsdk:"assign_self_as_owner"`
	CertType                 types.String        `tfsdk:"cert_type"`
	CompromiseDate           types.String        `tfsdk:"compromise_date"`
	CompromiseOccurrenceDate types.String        `tfsdk:"compromise_occurrence_date"`
	Curveid                  types.String        `tfsdk:"curveid"`
	DeactivationDate         types.String        `tfsdk:"deactivation_date"`
	DefaultIV                types.String        `tfsdk:"default_iv"`
	Description              types.String        `tfsdk:"description"`
	DestroyDate              types.String        `tfsdk:"destroy_date"`
	EmptyMaterial            types.Bool          `tfsdk:"empty_material"`
	Encoding                 types.String        `tfsdk:"encoding"`
	Format                   types.String        `tfsdk:"format"`
	GenerateKeyId            types.Bool          `tfsdk:"generate_key_id"`
	HKDFCreateParameters     HKDFParameters      `tfsdk:"hkdf_create_parameters"`
	IDSize                   types.Int64         `tfsdk:"id_size"`
	KeyId                    types.String        `tfsdk:"key_id"`
	MacSignBytes             types.String        `tfsdk:"mac_sign_bytes"`
	MacSignKeyIdentifier     types.String        `tfsdk:"mac_sign_key_identifier"`
	MacSignKeyIdentifierType types.String        `tfsdk:"mac_sign_key_identifier_type"`
	Material                 types.String        `tfsdk:"material"`
	MUID                     types.String        `tfsdk:"muid"`
	ObjectType               types.String        `tfsdk:"object_type"`
	Name                     types.String        `tfsdk:"name"`
	Metadata                 KeyMetadata         `tfsdk:"meta"`
	Padded                   types.Bool          `tfsdk:"padded"`
	Password                 types.String        `tfsdk:"password"`
	ProcessStartDate         types.String        `tfsdk:"process_start_date"`
	ProtectStopDate          types.String        `tfsdk:"protect_stop_date"`
	RevocationReason         types.String        `tfsdk:"revocation_reason"`
	RevocationMessage        types.String        `tfsdk:"revocation_message"`
	RotationFrequencyDays    types.String        `tfsdk:"rotation_frequency_days"`
	SecretDataEncoding       types.String        `tfsdk:"secret_data_encoding"`
	SecretDataLink           types.String        `tfsdk:"secret_data_link"`
	SigningAlgo              types.String        `tfsdk:"signing_algo"`
	Size                     types.Int64         `tfsdk:"size"`
	Exportable               types.Bool          `tfsdk:"unexportable"`
	Deletable                types.Bool          `tfsdk:"undeletable"`
	State                    types.String        `tfsdk:"state"`
	UsageMask                types.Int64         `tfsdk:"usage_mask"`
	UUID                     types.String        `tfsdk:"uuid"`
	WrapKeyIDType            types.String        `tfsdk:"wrap_key_id_type"`
	WrapKeyName              types.String        `tfsdk:"wrap_key_name"`
	WrapPublicKey            types.String        `tfsdk:"wrap_public_key"`
	WrapPublicKeyPadding     types.String        `tfsdk:"wrap_public_key_padding"`
	WrappingEncryptionAlgo   types.String        `tfsdk:"wrapping_encryption_algo"`
	WrappingHashAlgo         types.String        `tfsdk:"wrapping_hash_algo"`
	WrappingMethod           types.String        `tfsdk:"wrapping_method"`
	XTS                      types.Bool          `tfsdk:"xts"`
	Aliases                  []KeyAlias          `tfsdk:"aliases"`
	PublicKeyParameters      PublicKeyParameters `tfsdk:"public_key_parameters"`
	HKDFWrap                 WrapHKDF            `tfsdk:"wrap_hkdf"`
	PBEWrap                  WrapPBE             `tfsdk:"wrap_pbe"`
	RSAAESWrap               WrapRSAAES          `tfsdk:"wrap_rsaaes"`
}

func (r *resourceCMKey) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_key"
}

// Schema defines the schema for the resource.
func (r *resourceCMKey) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
			},
			"activation_date": schema.StringAttribute{
				Optional: true,
			},
			"algorithm": schema.StringAttribute{
				Optional: true,
			},
			"archive_date": schema.StringAttribute{
				Optional: true,
			},
			"assign_self_as_owner": schema.BoolAttribute{
				Optional: true,
			},
			"cert_type": schema.StringAttribute{
				Optional: true,
			},
			"compromise_date": schema.StringAttribute{
				Optional: true,
			},
			"compromise_occurrence_date": schema.StringAttribute{
				Optional: true,
			},
			"curveid": schema.StringAttribute{
				Optional: true,
			},
			"deactivation_date": schema.StringAttribute{
				Optional: true,
			},
			"default_iv": schema.StringAttribute{
				Optional: true,
			},
			"description": schema.StringAttribute{
				Optional: true,
			},
			"destroy_date": schema.StringAttribute{
				Optional: true,
			},
			"empty_material": schema.BoolAttribute{
				Optional: true,
			},
			"encoding": schema.StringAttribute{
				Optional: true,
			},
			"format": schema.StringAttribute{
				Optional: true,
			},
			"generate_key_id": schema.BoolAttribute{
				Optional: true,
			},
			"hkdf_create_parameters": schema.SingleNestedAttribute{
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"hash_algorithm": schema.StringAttribute{
						Optional: true,
					},
					"ikm_key_name": schema.StringAttribute{
						Optional: true,
					},
					"info": schema.StringAttribute{
						Optional: true,
					},
					"salt": schema.StringAttribute{
						Optional: true,
					},
				},
			},
			"id_size": schema.Int64Attribute{
				Optional: true,
			},
			"key_id": schema.StringAttribute{
				Optional: true,
			},
			"mac_sign_bytes": schema.StringAttribute{
				Optional: true,
			},
			"mac_sign_key_identifier": schema.StringAttribute{
				Optional: true,
			},
			"mac_sign_key_identifier_type": schema.StringAttribute{
				Optional: true,
			},
			"material": schema.StringAttribute{
				Optional: true,
			},
			"muid": schema.StringAttribute{
				Optional: true,
			},
			"object_type": schema.StringAttribute{
				Optional: true,
			},
			"name": schema.StringAttribute{
				Optional: true,
			},
			"meta": schema.SingleNestedAttribute{
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"owner_id": schema.StringAttribute{
						Optional: true,
					},
				},
			},
			"padded": schema.BoolAttribute{
				Optional: true,
			},
			"password": schema.StringAttribute{
				Optional: true,
			},
			"process_start_date": schema.StringAttribute{
				Optional: true,
			},
			"protect_stop_date": schema.StringAttribute{
				Optional: true,
			},
			"revocation_reason": schema.StringAttribute{
				Optional: true,
			},
			"revocation_message": schema.StringAttribute{
				Optional: true,
			},
			"rotation_frequency_days": schema.StringAttribute{
				Optional: true,
			},
			"secret_data_encoding": schema.StringAttribute{
				Optional: true,
			},
			"secret_data_link": schema.StringAttribute{
				Optional: true,
			},
			"signing_algo": schema.StringAttribute{
				Optional: true,
			},
			"size": schema.Int64Attribute{
				Optional: true,
			},
			"unexportable": schema.BoolAttribute{
				Optional: true,
			},
			"undeletable": schema.BoolAttribute{
				Optional: true,
			},
			"state": schema.StringAttribute{
				Optional: true,
			},
			"usage_mask": schema.Int64Attribute{
				Optional: true,
			},
			"uuid": schema.StringAttribute{
				Optional: true,
			},
			"wrap_key_id_type": schema.StringAttribute{
				Optional: true,
			},
			"wrap_key_name": schema.StringAttribute{
				Optional: true,
			},
			"wrap_public_key": schema.StringAttribute{
				Optional: true,
			},
			"wrap_public_key_padding": schema.StringAttribute{
				Optional: true,
			},
			"wrapping_encryption_algo": schema.StringAttribute{
				Optional: true,
			},
			"wrapping_hash_algo": schema.StringAttribute{
				Optional: true,
			},
			"wrapping_method": schema.StringAttribute{
				Optional: true,
			},
			"xts": schema.BoolAttribute{
				Optional: true,
			},
			"aliases": schema.ListNestedAttribute{
				Optional: true,
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
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"activation_date": schema.StringAttribute{
						Optional: true,
					},
					"archive_date": schema.StringAttribute{
						Optional: true,
					},
					"deactivation_date": schema.StringAttribute{
						Optional: true,
					},
					"name": schema.StringAttribute{
						Optional: true,
					},
					"state": schema.StringAttribute{
						Optional: true,
					},
					"undeletable": schema.BoolAttribute{
						Optional: true,
					},
					"unexportable": schema.BoolAttribute{
						Optional: true,
					},
					"usage_mask": schema.Int64Attribute{
						Optional: true,
					},
					"aliases": schema.ListNestedAttribute{
						Optional: true,
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
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"hash_algorithm": schema.StringAttribute{
						Optional: true,
					},
					"okm_len": schema.Int64Attribute{
						Optional: true,
					},
					"info": schema.StringAttribute{
						Optional: true,
					},
					"salt": schema.StringAttribute{
						Optional: true,
					},
				},
			},
			"wrap_pbe": schema.SingleNestedAttribute{
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"dklen": schema.Int64Attribute{
						Optional: true,
					},
					"hash_algorithm": schema.StringAttribute{
						Optional: true,
					},
					"salt": schema.StringAttribute{
						Optional: true,
					},
					"iteration": schema.Int64Attribute{
						Optional: true,
					},
					"password": schema.StringAttribute{
						Optional: true,
					},
					"password_identifier": schema.StringAttribute{
						Optional: true,
					},
					"password_identifier_type": schema.StringAttribute{
						Optional: true,
					},
					"purpose": schema.StringAttribute{
						Optional: true,
					},
				},
			},
			"wrap_rsaaes": schema.SingleNestedAttribute{
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"aes_key_size": schema.Int64Attribute{
						Optional: true,
					},
					"padding": schema.StringAttribute{
						Optional: true,
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMKey) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Retrieve values from plan
	var plan tfsdkCMKeyModel
	var payload Key

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Name = trimString(plan.Name.String())
	payload.Algorithm = trimString(plan.Algorithm.String())
	payload.Size = plan.Size.ValueInt64()
	payload.UsageMask = plan.UsageMask.ValueInt64()

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid data input: Key Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, URL_KEY_MANAGEMENT, payloadJSON, "id")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating key on CipherTrust Manager: ",
			"Could not create key, unexpected error: "+err.Error(),
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

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMKey) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMKey) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMKey) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

func (d *resourceCMKey) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
