package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDataSourceCMUsers(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: providerConfig + `data "ciphertrust_cm_users_list" "users_list" {}`,
				Check:  resource.ComposeAggregateTestCheckFunc(
				// Verify number of coffees returned
				//resource.TestCheckResourceAttr("data.users_list.test", "coffees.#", "9"),
				),
			},
		},
	})
}
