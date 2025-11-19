package okta

import (
	"context"
	"strings"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableOktaSignonPolicy() *plugin.Table {
	return &plugin.Table{
		Name:        "okta_signon_policy",
		Description: "Okta Sign On Policy controls the manner in which a user is allowed to sign on to Okta, including whether they are challenged for multifactor authentication (MFA) and how long they are allowed to remain signed in before re-authenticating.",
		List: &plugin.ListConfig{
			Hydrate: listOktaSignonPolicies,
		},
		Columns: commonColumns([]*plugin.Column{
			// Top Columns
			{Name: "name", Type: proto.ColumnType_STRING, Description: "Name of the Policy."},
			{Name: "id", Type: proto.ColumnType_STRING, Description: "Identifier of the Policy."},
			{Name: "description", Type: proto.ColumnType_STRING, Description: "Description of the Policy."},
			{Name: "created", Type: proto.ColumnType_TIMESTAMP, Description: "Timestamp when the Policy was created."},

			// Other Columns
			{Name: "last_updated", Type: proto.ColumnType_TIMESTAMP, Description: "Timestamp when the Policy was last modified."},
			{Name: "priority", Type: proto.ColumnType_INT, Description: "Priority of the Policy."},
			{Name: "status", Type: proto.ColumnType_STRING, Description: "Status of the Policy: ACTIVE or INACTIVE."},
			{Name: "system", Type: proto.ColumnType_BOOL, Description: "This is set to true on system policies, which cannot be deleted."},

			// JSON Columns
			{Name: "conditions", Type: proto.ColumnType_JSON, Description: "Conditions for Policy."},
			{Name: "rules", Type: proto.ColumnType_JSON, Hydrate: getOktaPolicyRules, Transform: transform.FromValue(), Description: "Each Policy may contain one or more Rules. Rules, like Policies, contain conditions that must be satisfied for the Rule to be applied."},
			{Name: "resource_mapping", Type: proto.ColumnType_JSON, Hydrate: getOktaPolicyAssociatedResources, Transform: transform.FromValue(), Description: "The resources that are mapped to the Policy."},

			// Steampipe Columns
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Name"), Description: titleDescription},
		}),
	}
}

func listOktaSignonPolicies(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	client, err := Connect(ctx, d)

	if err != nil {
		logger.Error("listOktaSignonPolicies", "connect_error", err)
		return nil, err
	}

	policyResp, resp, err := client.PolicyAPI.ListPolicies(ctx).Type_("OKTA_SIGN_ON").Execute()
	if err != nil {
		logger.Error("listOktaSignonPolicies", "list_policies_error", err)
		return nil, err
	}

	// In v6, ListPolicies returns a single policy union type, not an array
	// Stream the first policy if it exists
	if policyResp != nil {
		if actual := policyResp.GetActualInstance(); actual != nil {
			d.StreamListItem(ctx, *policyResp)
			
			// Context can be cancelled due to manual cancellation or the limit has been hit
			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}

	// paging - try to get more policies through pagination
	for resp.HasNextPage() {
		var nextPolicy okta.ListPolicies200Response
		resp, err = resp.Next(&nextPolicy)
		if err != nil {
			logger.Error("listOktaSignonPolicies", "list_policies_paging_error", err)
			return nil, err
		}
		if actual := nextPolicy.GetActualInstance(); actual != nil {
			d.StreamListItem(ctx, nextPolicy)

			// Context can be cancelled due to manual cancellation or the limit has been hit
			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}

	return nil, err
}

//// HYDRATE FUNCTION

func getOktaPolicyRules(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	if h.Item == nil {
		return nil, nil
	}
	policyId := ""

	switch item := h.Item.(type) {
	case *PolicyStructure:
		policyId = item.Id
	case *okta.Policy:
		policyId = *item.Id
	case *okta.AuthorizationServerPolicy:
		policyId = *item.Id
	case okta.ListPolicies200Response:
		// Handle union type - extract actual policy
		if actual := item.GetActualInstance(); actual != nil {
			switch p := actual.(type) {
			case *okta.AccessPolicy:
				policyId = *p.Id
			case *okta.IdpDiscoveryPolicy:
				policyId = *p.Id
			case *okta.AuthenticatorEnrollmentPolicy:
				policyId = *p.Id
			case *okta.OktaSignOnPolicy:
				policyId = *p.Id
			case *okta.PasswordPolicy:
				policyId = *p.Id
			}
		}
	}

	// Empty check
	if policyId == "" {
		return nil, nil
	}

	client, err := Connect(ctx, d)
	if err != nil {
		logger.Error("getOktaPolicyRules", "connect_error", err)
		return nil, err
	}

	var rules []okta.ListPolicyRules200ResponseInner

	policyRules, resp, err := client.PolicyAPI.ListPolicyRules(ctx, policyId).Execute()
	if err != nil {
		logger.Error("getOktaPolicyRules", "list_policies_error", err)
		return nil, err
	}

	rules = append(rules, policyRules...)

	// paging
	for resp.HasNextPage() {
		var nextPolicyRules []okta.ListPolicyRules200ResponseInner
		resp, err = resp.Next(&nextPolicyRules)
		if err != nil {
			logger.Error("getOktaPolicyRules", "list_policies_paging_error", err)
			return nil, err
		}
		rules = append(rules, nextPolicyRules...)
	}

	var allRules []interface{}
	for _, rule := range rules {
		r := rule.GetActualInstance()
		// We need to extract the inner properties; otherwise, the values will be populated as null.
		result, err := structToMap(r)
		if err != nil {
			logger.Error("getOktaPolicyRules", "error in parsing the rules for the policy:", policyId, err)
			return nil, err
		}
		allRules = append(allRules, result)
	}

	return allRules, nil
}

func getOktaPolicyAssociatedResources(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	if h.Item == nil {
		return nil, nil
	}
	policyId := ""

	switch item := h.Item.(type) {
	case *PolicyStructure:
		policyId = item.Id
	case *okta.Policy:
		policyId = *item.Id
	case *okta.AuthorizationServerPolicy:
		policyId = *item.Id
	}

	// Empty check
	if policyId == "" {
		return nil, nil
	}

	client, err := Connect(ctx, d)
	if err != nil {
		logger.Error("getOktaPolicyAssociatedResources", "connect_error", err)
		return nil, err
	}

	var mappings []okta.PolicyMapping

	policyMappings, resp, err := client.PolicyAPI.ListPolicyMappings(ctx, policyId).Execute()
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") || strings.Contains(err.Error(), "404") {
			return nil, nil
		}
		logger.Error("getOktaPolicyAssociatedResources", "list_policies_error", err)
		return nil, err
	}

	mappings = append(mappings, policyMappings...)

	// paging
	for resp.HasNextPage() {
		var nextPolicyMappings []okta.PolicyMapping
		resp, err = resp.Next(&nextPolicyMappings)
		if err != nil {
			logger.Error("getOktaPolicyAssociatedResources", "list_policies_paging_error", err)
			return nil, err
		}

		for _, mapping := range nextPolicyMappings {
			mappings = append(mappings, mapping)
		}
	}

	return mappings, nil
}
