package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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

func (r *resourceCMKey) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_key"
}

// Schema defines the schema for the resource.
func (r *resourceCMKey) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"activation_date": schema.StringAttribute{
				Optional:    true,
				Description: "Date/time the object becomes active",
			},
			"algorithm": schema.StringAttribute{
				Optional:    true,
				Description: "Cryptographic algorithm this key is used with. Defaults to 'aes'",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"aes",
						"tdes",
						"rsa",
						"ec",
						"hmac-sha1",
						"hmac-sha256",
						"hmac-sha384",
						"hmac-sha512",
						"seed",
						"aria",
						"opaque"}...),
				},
			},
			"aliases": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Aliases associated with the key. The alias and alias-type must be specified. The alias index is assigned by this operation, and need not be specified.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"alias": schema.StringAttribute{
							Optional:    true,
							Description: "An alias for a key name.",
						},
						"index": schema.StringAttribute{
							Optional:    true,
							Description: "Index associated with alias. Each alias within an object has a unique index.",
						},
						"type": schema.StringAttribute{
							Optional:    true,
							Description: "Type of alias (allowed values are string and uri).",
							Validators: []validator.String{
								stringvalidator.OneOf([]string{"string",
									"uri"}...),
							},
						},
					},
				},
			},
			"archive_date": schema.StringAttribute{
				Optional:    true,
				Description: "Date/time the object becomes archived",
			},
			"assign_self_as_owner": schema.BoolAttribute{
				Optional:    true,
				Description: "If set to true, the user who is creating the key is set as the key owner. Specify either assignSelfAsOwner or ownerId in the meta, not both. Specifying both in the meta returns an error.",
			},
			"cert_type": schema.StringAttribute{
				Optional:    true,
				Description: "This specifies the type of certificate object that is being created. Valid values are 'x509-pem' and 'x509-der'. At present, we only support x.509 certificates. The cerfificate data is passed in via the 'material' field. The certificate type is infered from the material if it is left blank.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"x509-pem",
						"x509-der"}...),
				},
			},
			"compromise_date": schema.StringAttribute{
				Optional:    true,
				Description: "Date/time the object entered into the compromised state.",
			},
			"compromise_occurrence_date": schema.StringAttribute{
				Optional:    true,
				Description: "Date/time when the object was first believed to be compromised, if known. Only valid if the revocation reason is CACompromise or KeyCompromise, otherwise ignored.",
			},
			"curveid": schema.StringAttribute{
				Optional:    true,
				Description: "Cryptographic curve id for elliptic key. Key algorithm must be 'EC'.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"secp224k1",
						"secp224r1",
						"secp256k1",
						"secp384r1",
						"secp521r1",
						"prime256v1",
						"brainpoolP224r1",
						"brainpoolP224t1",
						"brainpoolP256r1",
						"brainpoolP256t1",
						"brainpoolP384r1",
						"brainpoolP384t1",
						"brainpoolP512r1",
						"brainpoolP512t1",
						"curve25519"}...),
				},
			},
			"deactivation_date": schema.StringAttribute{
				Optional:    true,
				Description: "Date/time the object becomes inactive",
			},
			"default_iv": schema.StringAttribute{
				Optional:    true,
				Description: "Deprecated. This field was introduced to support specific legacy integrations and applications. New applications are strongly recommended to use a unique IV for each encryption request. Refer to Crypto encrypt endpoint for more details. Must be a 16 byte hex encoded string (32 characters long). If specified, this will be set as the default IV for this key.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "It store information about key",
			},
			"destroy_date": schema.StringAttribute{
				Optional:    true,
				Description: "Date/time the object was destroyed.",
			},
			"empty_material": schema.BoolAttribute{
				Optional:    true,
				Description: "If set to true, the key material is not created and left empty.",
			},
			"encoding": schema.StringAttribute{
				Optional:    true,
				Description: "Specifies the encoding used for the 'material' field.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"hex",
						"base64"}...),
				},
			},
			"format": schema.StringAttribute{
				Optional:    true,
				Description: "This parameter is used while importing keys ('material' is not empty), and also when returning the key material after the key is created ('includeMaterial' is true).\nFor Asymmetric keys: When this parameter is not specified, while importing keys, the format of the material is inferred from the material itself. When this parameter is specified, while importing keys, the only allowed format is 'pkcs12', and this only applies to the 'rsa' algorithm (the 'material' should contain the base64 encoded value of the PFX file in this case).\nWhen returning the key material, this parameter specifies the format of the returned key material.\nOptions are pkcs1, pkcs8 (default), pkcs12\nFor Symmetric keys: When importing keys if specified, the value must be given according to the format of the material.\nWhen returning the key material, this parameter specifies the format of the returned key material. Options are raw or opaque",
			},
			"generate_key_id": schema.BoolAttribute{
				Optional:    true,
				Description: "If specified as true, the key's keyId identifier of type long is generated. Defaults to false.",
			},
			"hkdf_create_parameters": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Information which is used to create a Key using HKDF.",
				Attributes: map[string]schema.Attribute{
					"hash_algorithm": schema.StringAttribute{
						Optional:    true,
						Description: "Hash Algorithm is used for HKDF. This is required if ikmKeyName is specified, default is hmac-sha256.",
						Validators: []validator.String{
							stringvalidator.OneOf([]string{"hmac-sha1",
								"hmac-sha224",
								"hmac-sha256",
								"hmac-sha384",
								"hmac-sha512"}...),
						},
					},
					"ikm_key_name": schema.StringAttribute{
						Optional:    true,
						Description: "Any existing symmetric key. Mandatory while using HKDF key generation.",
					},
					"info": schema.StringAttribute{
						Optional:    true,
						Description: "Info is an optional hex value for HKDF based derivation.",
					},
					"salt": schema.StringAttribute{
						Optional:    true,
						Description: "Salt is an optional hex value for HKDF based derivation.",
					},
				},
			},
			"id_size": schema.Int64Attribute{
				Optional:    true,
				Description: "Size of the ID for the key",
			},
			"key_id": schema.StringAttribute{
				Optional:    true,
				Description: "Additional identifier of the key. The format of this value is of type long. This is optional and applicable for import key only. If set, the value is imported as the key's keyId.",
			},
			"mac_sign_bytes": schema.StringAttribute{
				Optional:    true,
				Description: "This parameter specifies the MAC/Signature bytes to be used for verification while importing a key. The wrappingMethod should be mac/sign and the required parameters for the verification must be set.",
			},
			"mac_sign_key_identifier": schema.StringAttribute{
				Optional:    true,
				Description: "This parameter specifies the identifier of the key to be used for generating MAC or signature of the key material. The wrappingMethod should be mac/sign to verify the MAC/signature(macSignBytes) of the key material(material). For verifying the MAC, the key has to be a HMAC key. For verifying the signature, the key has to be an RSA private or public key.",
			},
			"mac_sign_key_identifier_type": schema.StringAttribute{
				Optional:    true,
				Description: "This parameter specifies the identifier of the key(macSignKeyIdentifier) used for generating MAC or signature of the key material. The wrappingMethod should be mac/sign to verify the mac/signature(macSignBytes) of the key material(material).",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"name",
						"id",
						"alias"}...),
				},
			},
			"material": schema.StringAttribute{
				Optional:    true,
				Description: "If set, the value will be imported as the key's material. If not set, new key material will be generated on the server (certificate objects must always specify the material). The format of this value depends on the algorithm. If the algorithm is 'aes', 'tdes', 'hmac-*', 'seed' or 'aria', the value should be the hex-encoded bytes of the key material. If the algorithm is 'rsa', and the format is 'pkcs12', it should be the base64 encoded PFX file. If the algorithm is 'rsa' or 'ec', and format is not 'pkcs12', the value should be a PEM-encoded private or public key using PKCS1 or PKCS8 format. For a X.509 DER encoded certificate, certType equals 'x509-der' and the material should equal the hex encoded certificate. The material for a X.509 PEM encoded certificate (certType = 'x509-pem') should equal the certificate itself. When placing the PEM encoded certificate inside a JSON object (as in the playground), be sure to change all new line characters in the certificate to the string '\\n'.",
			},
			"muid": schema.StringAttribute{
				Optional:    true,
				Description: "Additional identifier of the key. This is optional and applicable for import key only. If set, the value is imported as the key's muid.",
			},
			"object_type": schema.StringAttribute{
				Optional:    true,
				Description: "This specifies the type of object that is being created. Valid values are 'Symmetric Key', 'Public Key', 'Private Key', 'Secret Data', 'Opaque Object', or 'Certificate'. The object type is inferred for many objects, but must be supplied for the certificate object.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"Symmetric Key",
						"Public Key",
						"Private Key",
						"Secret Data",
						"Opaque Object",
						"Certificate"}...),
				},
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Description: "Optional friendly name, The key name should not contain special characters such as angular brackets (<,>) and backslash (\\).",
			},
			"meta": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Optional end-user or service data stored with the key",
				Attributes: map[string]schema.Attribute{
					"owner_id": schema.StringAttribute{
						Optional:    true,
						Description: "Optional owner information for the key, required for non-admin. Value should be the user's user_id",
					},
				},
			},
			"padded": schema.BoolAttribute{
				Optional:    true,
				Description: "This parameter determines the padding for the wrap algorithm while unwrapping a symmetric key,\nif wrappingMethod is encrypt and the wrappingEncryptionAlgo doesn't have a mode set\nif wrappingMethod is pbe.\nIf true, the RFC 5649(AES Key Wrap with Padding) is followed and if false, RFC 3394(AES Key Wrap) is followed for unwrapping the material for the symmetric key.\nIf a certificate is being unwrapped with the wrappingMethod set to encrypt, the padded parameter has to be set to true. This parameter defaults to false.",
			},
			"password": schema.StringAttribute{
				Optional:    true,
				Description: "For pkcs12 format, either password or secretDataLink should be specified. This should be the base64 encoded value of the password.",
			},
			"process_start_date": schema.StringAttribute{
				Optional:    true,
				Description: "Date/time when a Managed Symmetric Key Object MAY begin to be used to process cryptographically protected information (e.g., decryption or unwrapping)",
			},
			"protect_stop_date": schema.StringAttribute{
				Optional:    true,
				Description: "Date/time after which a Managed Symmetric Key Object SHALL NOT be used for applying cryptographic protection (e.g., encryption or wrapping)",
			},
			"revocation_reason": schema.StringAttribute{
				Optional:    true,
				Description: "The reason the key is being revoked.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"Unspecified",
						"KeyCompromise",
						"CACompromise",
						"AffiliationChanged",
						"Superseded",
						"CessationOfOperation",
						"PrivilegeWithdrawn"}...),
				},
			},
			"revocation_message": schema.StringAttribute{
				Optional:    true,
				Description: "Message explaining revocation.",
			},
			"rotation_frequency_days": schema.StringAttribute{
				Optional:    true,
				Description: "Number of days from current date to rotate the key. It should be greater than or equal to 0. Default is an empty string. If set to 0, rotationFrequencyDays set to an empty string and auto rotation of key will be disabled.",
			},
			"secret_data_encoding": schema.StringAttribute{
				Optional:    true,
				Description: "For pkcs12 format, this field specifies the encoding method used for the secretDataLink material. Ignore this field if secretData is created from REST and is in plain format. Specify the value of this field as HEX format if secretData is created from KMIP.",
			},
			"secret_data_link": schema.StringAttribute{
				Optional:    true,
				Description: "For pkcs12 format, either secretDataLink or password should be specified. The value can be either ID or name of Secret Data.",
			},
			"signing_algo": schema.StringAttribute{
				Optional:    true,
				Description: "This parameter specifies the algorithm to be used for generating the signature for the verification of the macSignBytes during import of key material. The wrappingMethod should be mac/sign to verify the signature(macSignBytes) of the key material(material).",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"RSA",
						"RSA-PSS"}...),
				},
			},
			"size": schema.Int64Attribute{
				Optional:    true,
				Description: "Bit length for the key.",
			},
			"unexportable": schema.BoolAttribute{
				Optional:    true,
				Description: "Key is not exportable. Defaults to false.",
			},
			"undeletable": schema.BoolAttribute{
				Optional:    true,
				Description: "Key is not deletable. Defaults to false.",
			},
			"state": schema.StringAttribute{
				Optional:    true,
				Description: "Optional initial key state (Pre-Active) upon creation. Defaults to Active. If set, activationDate and processStartDate can not be specified during key creation. In case of import, allowed values are Pre-Active, Active, Deactivated, Destroyed, Compromised and Destroyed Compromised. If key material is not specified, it will not be autogenerated if input parameters correspond to either of these states - Deactivated, Destroyed, Compromised and Destroyed Compromised. Key in Destroyed or Destroyed Compromised state would not have key material even if specified during key creation.",
			},
			"usage_mask": schema.Int64Attribute{
				Optional:    true,
				Description: "Cryptographic usage mask. Add the usage masks to allow certain usages. Sign (1), Verify (2), Encrypt (4), Decrypt (8), Wrap Key (16), Unwrap Key (32), Export (64), MAC Generate (128), MAC Verify (256), Derive Key (512), Content Commitment (1024), Key Agreement (2048), Certificate Sign (4096), CRL Sign (8192), Generate Cryptogram (16384), Validate Cryptogram (32768), Translate Encrypt (65536), Translate Decrypt (131072), Translate Wrap (262144), Translate Unwrap (524288), FPE Encrypt (1048576), FPE Decrypt (2097152). Add the usage mask values to allow the usages. To set all usage mask bits, use 4194303. Equivalent usageMask values for deprecated usages 'fpe' (FPE Encrypt + FPE Decrypt = 3145728), 'blob' (Encrypt + Decrypt = 12), 'hmac' (MAC Generate + MAC Verify = 384), 'encrypt' (Encrypt + Decrypt = 12), 'sign' (Sign + Verify = 3), 'any' (4194303 - all usage masks).",
			},
			"uuid": schema.StringAttribute{
				Optional:    true,
				Description: "Additional identifier of the key. The format of this value is 32 hexadecimal lowercase digits with 4 dashes. This is optional and applicable for import key only.\nIf set, the value is imported as the key's uuid.\nIf not set, new key uuid is generated on the server.",
			},
			"wrap_key_id_type": schema.StringAttribute{
				Optional:    true,
				Description: "IDType specifies how the wrapKeyName should be interpreted.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"name",
						"id",
						"alias"}...),
				},
			},
			"wrap_key_name": schema.StringAttribute{
				Optional:    true,
				Description: "While creating a new key, If 'includeMaterial' is true, then only the key material will be wrapped with material of the specified key name. The response material property will be the base64 encoded ciphertext. For more details, view wrapKeyName in export parameters.\nWhile importing a key, the key material will be unwrapped with material of the specified key name. The only applicable wrappingMethod for the unwrapping is encrypt and the wrapping key has to be an AES key or an RSA private key.",
			},
			"wrap_public_key": schema.StringAttribute{
				Optional:    true,
				Description: "If the algorithm is 'aes','tdes','hmac-*', 'seed' or 'aria', this value will be used to encrypt the returned key material. This value is ignored for other algorithms. Value must be an RSA public key, PEM-encoded public key in either PKCS1 or PKCS8 format, or a PEM-encoded X.509 certificate. If set, the returned 'material' value will be a Base64 encoded PKCS#1 v1.5 encrypted key. View wrapPublicKey in export parameters for more information. Only applicable if 'includeMaterial' is true.",
			},
			"wrap_public_key_padding": schema.StringAttribute{
				Optional:    true,
				Description: "WrapPublicKeyPadding specifies the type of padding scheme that needs to be set when importing the Key using the specified wrapkey. Accepted values are pkcs1, oaep, oaep256, oaep384, oaep512, and will default to pkcs1 when 'wrapPublicKeyPadding' is not set and 'WrapPublicKey' is set.\nWhile creating a new key, wrapPublicKeyPadding parameter should be specified only if 'includeMaterial' is true. In this case, key will get created and in response wrapped material using specified wrapPublicKeyPadding and other wrap parameters will be returned.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"pkcs1",
						"oaep",
						"oaep256",
						"oaep384",
						"oaep512"}...),
				},
			},
			"wrapping_encryption_algo": schema.StringAttribute{
				Optional:    true,
				Description: "It indicates the Encryption Algorithm information for wrapping the key. Format is : Algorithm/Mode/Padding. For example : AES/AESKEYWRAP. Here AES is Algorithm, AESKEYWRAP is Mode & Padding is not specified. AES/AESKEYWRAP is RFC-3394 & AES/AESKEYWRAPPADDING is RFC-5649. For wrapping private key, only AES/AESKEYWRAPPADDING is allowed. RSA/RSAAESKEYWRAPPADDING is used to wrap/unwrap asymmetric keys using RSA AES KWP method. Refer WrapRSAAES to provide optional parameters.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"AES/AESKEYWRAP",
						"AES/AESKEYWRAPPADDING",
						"RSA/RSAAESKEYWRAPPADDING"}...),
				},
			},
			"wrapping_hash_algo": schema.StringAttribute{
				Optional:    true,
				Description: "This parameter specifies the hashing algorithm used if wrappingMethod corresponds to mac/sign. In case of MAC operation, the hashing algorithm used will be inferred from the type of HMAC key(macSignKeyIdentifier).",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"sha1",
						"sha224",
						"sha256",
						"sha384",
						"sha512"}...),
				},
			},
			"wrapping_method": schema.StringAttribute{
				Optional:    true,
				Description: "This parameter specifies the wrapping method used to wrap/mac/sign the key material",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"encrypt",
						"mac/sign",
						"pbe"}...),
				},
			},
			"xts": schema.BoolAttribute{
				Optional:    true,
				Description: "If set to true, then key created will be XTS/CBC-CS1 Key. Defaults to false. Key algorithm must be 'AES'.",
			},
			"public_key_parameters": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Information needed to create a public key.",
				Attributes: map[string]schema.Attribute{
					"activation_date": schema.StringAttribute{
						Optional:    true,
						Description: "Date/time the object becomes active",
					},
					"archive_date": schema.StringAttribute{
						Optional:    true,
						Description: "Date/time the object becomes archived",
					},
					"deactivation_date": schema.StringAttribute{
						Optional:    true,
						Description: "Date/time the object becomes inactive",
					},
					"name": schema.StringAttribute{
						Optional:    true,
						Description: "Friendly name of the corresponding public key",
					},
					"state": schema.StringAttribute{
						Optional:    true,
						Description: "Optional initial key state (Pre-Active) upon creation. If set, activationDate and processStartDate can not be specified during key creation. Defaults to Active.",
					},
					"undeletable": schema.BoolAttribute{
						Optional:    true,
						Description: "Key is not deletable. Defaults to false.",
					},
					"unexportable": schema.BoolAttribute{
						Optional:    true,
						Description: "Key is not exportable. Defaults to false.",
					},
					"usage_mask": schema.Int64Attribute{
						Optional:    true,
						Description: "Defined in PostKey parameters",
					},
					"aliases": schema.ListNestedAttribute{
						Optional:    true,
						Description: "",
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"alias": schema.StringAttribute{
									Required:    true,
									Description: "An alias for a key name.",
								},
								"index": schema.Int64Attribute{
									Required:    true,
									Description: "Index associated with alias. Each alias within an object has a unique index.",
								},
								"type": schema.StringAttribute{
									Required:    true,
									Description: "Type of alias (allowed values are string and uri).",
									Validators: []validator.String{
										stringvalidator.OneOf([]string{"string",
											"uri"}...),
									},
								},
							},
						},
					},
				},
			},
			"wrap_hkdf": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Information which is used to wrap a Key using HKDF.",
				Attributes: map[string]schema.Attribute{
					"hash_algorithm": schema.StringAttribute{
						Optional:    true,
						Description: "Hash Algorithm is used for HKDF Wrapping.",
						Validators: []validator.String{
							stringvalidator.OneOf([]string{"hmac-sha1",
								"hmac-sha224",
								"hmac-sha256",
								"hmac-sha384",
								"hmac-sha512"}...),
						},
					},
					"okm_len": schema.Int64Attribute{
						Optional:    true,
						Description: "The desired output key material length in integer.",
					},
					"info": schema.StringAttribute{
						Optional:    true,
						Description: "Info is an optional hex value for HKDF based derivation.",
					},
					"salt": schema.StringAttribute{
						Optional:    true,
						Description: "Salt is an optional hex value for HKDF based derivation.",
					},
				},
			},
			"wrap_pbe": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "WrapPBE derives the key from the password and other parameters such as salt, iteration count, hashing algorithm, and derived key-length. PBE currently supports wrapping of symmetric keys (AES), private keys, and certificates. WrapPBE is a two-step process to export a key as mentioned below. The key import is similar to the key export but it unwraps the target key in the second step. Step 1 Use PBKDF2 with the specified parameters (pwd, hash-function, salt, iterations, purpose (opt), KEK length) to derive the KEK. For more details, refer to RFC 2898. Step 2 Perform AES-KW/KWP to wrap the target key using the KEK derived from Step 1. The AES KEK size is calculated by the KEK length parameter as described in Step 1. For more details, refer to RFC 3394 and 5649.",
				Attributes: map[string]schema.Attribute{
					"dklen": schema.Int64Attribute{
						Optional:    true,
						Description: "Intended length in octets of the derived key. dklen must be in range of 14 bytes to 512 bytes.",
					},
					"hash_algorithm": schema.StringAttribute{
						Optional:    true,
						Description: "Underlying hashing algorithm that acts as a pseudorandom function to generate derive keys.",
						Validators: []validator.String{
							stringvalidator.OneOf([]string{"hmac-sha1",
								"hmac-sha224",
								"hmac-sha256",
								"hmac-sha384",
								"hmac-sha512",
								"hmac-sha512/224",
								"hmac-sha512/256",
								"hmac-sha3-224",
								"hmac-sha3-256",
								"hmac-sha3-384",
								"hmac-sha3-512"}...),
						},
					},
					"salt": schema.StringAttribute{
						Optional:    true,
						Description: "A Hex encoded string. pbeSalt must be in range of 16 bytes to 512 bytes.",
						Validators: []validator.String{
							stringvalidator.LengthBetween(16, 512),
						},
					},
					"iteration": schema.Int64Attribute{
						Optional:    true,
						Description: "Iteration count increase the cost of producing keys from a password. Iteration must be in range of 1 to 1,00,00,000.",
						Validators: []validator.Int64{
							int64validator.Between(1, 10000000),
						},
					},
					"password": schema.StringAttribute{
						Optional:    true,
						Description: "Base password to generate derive keys. It cannot be used in conjunction with passwordidentifier. password must be in range of 8 bytes to 128 bytes.",
						Validators: []validator.String{
							stringvalidator.LengthBetween(8, 128),
						},
					},
					"password_identifier": schema.StringAttribute{
						Optional:    true,
						Description: "Secret password identifier for password. It cannot be used in conjunction with password.",
					},
					"password_identifier_type": schema.StringAttribute{
						Optional:    true,
						Description: "Type of the Passwordidentifier. If not set then default value is name.",
						Validators: []validator.String{
							stringvalidator.OneOf([]string{"id",
								"name",
								"slug"}...),
						},
						Default: stringdefault.StaticString("name"),
					},
					"purpose": schema.StringAttribute{
						Optional:    true,
						Description: "User defined purpose. If specified will be prefixed to pbeSalt. pbePurpose must not be greater than 128 bytes.",
					},
				},
			},
			"wrap_rsaaes": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "",
				Attributes: map[string]schema.Attribute{
					"aes_key_size": schema.Int64Attribute{
						Optional:    true,
						Description: "Size of AES key for RSA AES KWP. Accepted value are 128, 192, 256. Default value is 256.",
						Validators: []validator.Int64{
							int64validator.OneOf([]int64{128,
								192,
								256}...),
						},
						Default: int64default.StaticInt64(256),
					},
					"padding": schema.StringAttribute{
						Optional:    true,
						Description: "Padding specifies the type of padding scheme that needs to be set when exporting the Key using RSA AES wrap.",
						Validators: []validator.String{
							stringvalidator.OneOf([]string{"oaep",
								"oaep256",
								"oaep384",
								"oaep512"}...),
						},
						Default: stringdefault.StaticString("oaep256"),
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMKey) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, MSG_METHOD_START+"[resource_cm_key.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan tfsdkCMKeyModel
	var payload jsonCMKeyModel

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.ActivationDate.ValueString() != "" && plan.ActivationDate.ValueString() != types.StringNull().ValueString() {
		payload.ActivationDate = plan.ActivationDate.ValueString()
	}
	if plan.Algorithm.ValueString() != "" && plan.Algorithm.ValueString() != types.StringNull().ValueString() {
		payload.Algorithm = plan.Algorithm.ValueString()
	}
	if plan.ArchiveDate.ValueString() != "" && plan.ArchiveDate.ValueString() != types.StringNull().ValueString() {
		payload.ArchiveDate = plan.ArchiveDate.ValueString()
	}
	if plan.AssignSelfAsOwner.ValueBool() != types.BoolNull().ValueBool() {
		payload.AssignSelfAsOwner = plan.AssignSelfAsOwner.ValueBool()
	}
	if plan.CertType.ValueString() != "" && plan.CertType.ValueString() != types.StringNull().ValueString() {
		payload.CertType = plan.CertType.ValueString()
	}
	if plan.CompromiseDate.ValueString() != "" && plan.CompromiseDate.ValueString() != types.StringNull().ValueString() {
		payload.CompromiseDate = plan.CompromiseDate.ValueString()
	}
	if plan.CompromiseOccurrenceDate.ValueString() != "" && plan.CompromiseOccurrenceDate.ValueString() != types.StringNull().ValueString() {
		payload.CompromiseOccurrenceDate = plan.CompromiseOccurrenceDate.ValueString()
	}
	if plan.Curveid.ValueString() != "" && plan.Curveid.ValueString() != types.StringNull().ValueString() {
		payload.Curveid = plan.Curveid.ValueString()
	}
	if plan.DeactivationDate.ValueString() != "" && plan.DeactivationDate.ValueString() != types.StringNull().ValueString() {
		payload.DeactivationDate = plan.DeactivationDate.ValueString()
	}
	if plan.DefaultIV.ValueString() != "" && plan.DefaultIV.ValueString() != types.StringNull().ValueString() {
		payload.DefaultIV = plan.DefaultIV.ValueString()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}
	if plan.DestroyDate.ValueString() != "" && plan.DestroyDate.ValueString() != types.StringNull().ValueString() {
		payload.DestroyDate = plan.DestroyDate.ValueString()
	}
	if plan.EmptyMaterial.ValueBool() != types.BoolNull().ValueBool() {
		payload.EmptyMaterial = plan.EmptyMaterial.ValueBool()
	}
	if plan.Encoding.ValueString() != "" && plan.Encoding.ValueString() != types.StringNull().ValueString() {
		payload.Encoding = plan.Encoding.ValueString()
	}
	if plan.Format.ValueString() != "" && plan.Format.ValueString() != types.StringNull().ValueString() {
		payload.Format = plan.Format.ValueString()
	}
	if plan.GenerateKeyId.ValueBool() != types.BoolNull().ValueBool() {
		payload.GenerateKeyId = plan.GenerateKeyId.ValueBool()
	}
	if plan.ID.ValueString() != "" && plan.ID.ValueString() != types.StringNull().ValueString() {
		payload.ID = plan.ID.ValueString()
	}
	if plan.IDSize.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.IDSize = plan.IDSize.ValueInt64()
	}
	if plan.KeyId.ValueString() != "" && plan.KeyId.ValueString() != types.StringNull().ValueString() {
		payload.KeyId = plan.KeyId.ValueString()
	}
	if plan.MacSignBytes.ValueString() != "" && plan.MacSignBytes.ValueString() != types.StringNull().ValueString() {
		payload.MacSignBytes = plan.MacSignBytes.ValueString()
	}
	if plan.MacSignKeyIdentifier.ValueString() != "" && plan.MacSignKeyIdentifier.ValueString() != types.StringNull().ValueString() {
		payload.MacSignKeyIdentifier = plan.MacSignKeyIdentifier.ValueString()
	}
	if plan.MacSignKeyIdentifierType.ValueString() != "" && plan.MacSignKeyIdentifierType.ValueString() != types.StringNull().ValueString() {
		payload.MacSignKeyIdentifierType = plan.MacSignKeyIdentifierType.ValueString()
	}
	if plan.Material.ValueString() != "" && plan.Material.ValueString() != types.StringNull().ValueString() {
		payload.Material = plan.Material.ValueString()
	}
	if plan.MUID.ValueString() != "" && plan.MUID.ValueString() != types.StringNull().ValueString() {
		payload.MUID = plan.MUID.ValueString()
	}
	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		payload.Name = plan.Name.ValueString()
	}
	if plan.ObjectType.ValueString() != "" && plan.ObjectType.ValueString() != types.StringNull().ValueString() {
		payload.ObjectType = plan.ObjectType.ValueString()
	}
	if plan.Padded.ValueBool() != types.BoolNull().ValueBool() {
		payload.Padded = plan.Padded.ValueBool()
	}
	if plan.Password.ValueString() != "" && plan.Password.ValueString() != types.StringNull().ValueString() {
		payload.Password = plan.Password.ValueString()
	}
	if plan.ProcessStartDate.ValueString() != "" && plan.ProcessStartDate.ValueString() != types.StringNull().ValueString() {
		payload.ProcessStartDate = plan.ProcessStartDate.ValueString()
	}
	if plan.ProtectStopDate.ValueString() != "" && plan.ProtectStopDate.ValueString() != types.StringNull().ValueString() {
		payload.ProtectStopDate = plan.ProtectStopDate.ValueString()
	}
	if plan.RevocationMessage.ValueString() != "" && plan.RevocationMessage.ValueString() != types.StringNull().ValueString() {
		payload.RevocationMessage = plan.RevocationMessage.ValueString()
	}
	if plan.RevocationReason.ValueString() != "" && plan.RevocationReason.ValueString() != types.StringNull().ValueString() {
		payload.RevocationReason = plan.RevocationReason.ValueString()
	}
	if plan.RotationFrequencyDays.ValueString() != "" && plan.RotationFrequencyDays.ValueString() != types.StringNull().ValueString() {
		payload.RotationFrequencyDays = plan.RotationFrequencyDays.ValueString()
	}
	if plan.SecretDataEncoding.ValueString() != "" && plan.SecretDataEncoding.ValueString() != types.StringNull().ValueString() {
		payload.SecretDataEncoding = plan.SecretDataEncoding.ValueString()
	}
	if plan.SecretDataLink.ValueString() != "" && plan.SecretDataLink.ValueString() != types.StringNull().ValueString() {
		payload.SecretDataLink = plan.SecretDataLink.ValueString()
	}
	if plan.SigningAlgo.ValueString() != "" && plan.SigningAlgo.ValueString() != types.StringNull().ValueString() {
		payload.SigningAlgo = plan.SigningAlgo.ValueString()
	}
	if plan.Size.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.Size = plan.Size.ValueInt64()
	}
	if plan.State.ValueString() != "" && plan.State.ValueString() != types.StringNull().ValueString() {
		payload.State = plan.State.ValueString()
	}
	if plan.TemplateID.ValueString() != "" && plan.TemplateID.ValueString() != types.StringNull().ValueString() {
		payload.TemplateID = plan.TemplateID.ValueString()
	}
	if plan.Deletable.ValueBool() != types.BoolNull().ValueBool() {
		payload.Deletable = plan.Deletable.ValueBool()
	}
	if plan.Exportable.ValueBool() != types.BoolNull().ValueBool() {
		payload.Exportable = plan.Exportable.ValueBool()
	}
	if plan.UsageMask.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.UsageMask = plan.UsageMask.ValueInt64()
	}
	if plan.UUID.ValueString() != "" && plan.UUID.ValueString() != types.StringNull().ValueString() {
		payload.UUID = plan.UUID.ValueString()
	}
	if plan.WrapKeyIDType.ValueString() != "" && plan.WrapKeyIDType.ValueString() != types.StringNull().ValueString() {
		payload.WrapKeyIDType = plan.WrapKeyIDType.ValueString()
	}
	if plan.WrapKeyName.ValueString() != "" && plan.WrapKeyName.ValueString() != types.StringNull().ValueString() {
		payload.WrapKeyName = plan.WrapKeyName.ValueString()
	}
	if plan.WrapPublicKey.ValueString() != "" && plan.WrapPublicKey.ValueString() != types.StringNull().ValueString() {
		payload.WrapPublicKey = plan.WrapPublicKey.ValueString()
	}
	if plan.WrapPublicKeyPadding.ValueString() != "" && plan.WrapPublicKeyPadding.ValueString() != types.StringNull().ValueString() {
		payload.WrapPublicKeyPadding = plan.WrapPublicKeyPadding.ValueString()
	}
	if plan.WrappingEncryptionAlgo.ValueString() != "" && plan.WrappingEncryptionAlgo.ValueString() != types.StringNull().ValueString() {
		payload.WrappingEncryptionAlgo = plan.WrappingEncryptionAlgo.ValueString()
	}
	if plan.WrappingHashAlgo.ValueString() != "" && plan.WrappingHashAlgo.ValueString() != types.StringNull().ValueString() {
		payload.WrappingHashAlgo = plan.WrappingHashAlgo.ValueString()
	}
	if plan.WrappingMethod.ValueString() != "" && plan.WrappingMethod.ValueString() != types.StringNull().ValueString() {
		payload.WrappingMethod = plan.WrappingMethod.ValueString()
	}
	if plan.XTS.ValueBool() != types.BoolNull().ValueBool() {
		payload.XTS = plan.XTS.ValueBool()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_key.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Key Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, id, URL_KEY_MANAGEMENT, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_key.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating key on CipherTrust Manager: ",
			"Could not create key, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cm_key.go -> Create]["+id+"]")
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
	var plan tfsdkCMKeyModel
	payload := map[string]interface{}{}

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload["description"] = trimString(plan.Description.String())

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_key.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Key Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(ctx, plan.ID.ValueString(), URL_KEY_MANAGEMENT, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [resource_cm_key.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating key on CipherTrust Manager: ",
			"Could not upodate key, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cm_key.go -> Update]["+plan.ID.ValueString()+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMKey) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state tfsdkCMKeyModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	output, err := r.client.DeleteByID(ctx, state.ID.ValueString(), URL_KEY_MANAGEMENT)
	tflog.Trace(ctx, MSG_METHOD_END+"[resource_cm_key.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust Key",
			"Could not delete key, unexpected error: "+err.Error(),
		)
		return
	}
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
