package okta

import (
	"context"
	"time"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableOktaPasswordPolicy() *plugin.Table {
	return &plugin.Table{
		Name:        "okta_password_policy",
		Description: "The Password Policy determines the requirements for a user's password length and complexity, as well as the frequency with which a password must be changed. This Policy also governs the recovery operations that may be performed by the User, including change password, reset (forgot) password, and self-service password unlock.",
		List: &plugin.ListConfig{
			Hydrate: listPolicies,
		},
		Columns: commonColumns(listPoliciesWithSettingsColumns()),
	}
}

func listPoliciesWithSettingsColumns() []*plugin.Column {
	return []*plugin.Column{
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
		{Name: "settings", Type: proto.ColumnType_JSON, Description: "Settings of the password policy."},
		{Name: "resource_mapping", Type: proto.ColumnType_JSON, Hydrate: getOktaPolicyAssociatedResources, Transform: transform.FromValue(), Description: "The resources that are mapped to the Policy."},

		// Steampipe Columns
		{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Name"), Description: titleDescription},
	}
}

func listPolicies(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	client, err := Connect(ctx, d)

	if err != nil {
		logger.Error("listOktaPolicies", "connect_error", err)
		return nil, err
	}

	var policyType string
	switch d.Table.Name {
	case "okta_password_policy":
		policyType = "PASSWORD"
	case "okta_mfa_policy":
		policyType = "MFA_ENROLL"
	}

	policyResp, resp, err := client.PolicyAPI.ListPolicies(ctx).Type_(policyType).Execute()
	if err != nil {
		logger.Error("listPolicies", "list_policies_error", err)
		return nil, err
	}

	// In v6, ListPolicies returns a single policy union type, not an array
	// Convert it to PolicyStructure for compatibility
	if policyResp != nil {
		policyStruct := convertPolicyRespToStruct(policyResp)
		if policyStruct != nil {
			d.StreamListItem(ctx, policyStruct)
			
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
			logger.Error("listPolicies", "list_policies_paging_error", err)
			return nil, err
		}
		policyStruct := convertPolicyRespToStruct(&nextPolicy)
		if policyStruct != nil {
			d.StreamListItem(ctx, policyStruct)

			// Context can be cancelled due to manual cancellation or the limit has been hit
			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}

	return nil, err
}

// Convert v6 ListPolicies200Response union type to PolicyStructure
func convertPolicyRespToStruct(policyResp *okta.ListPolicies200Response) *PolicyStructure {
	if policyResp == nil {
		return nil
	}
	
	actual := policyResp.GetActualInstance()
	if actual == nil {
		return nil
	}

	switch p := actual.(type) {
	case *okta.PasswordPolicy:
		return &PolicyStructure{
			Id:          getStringPtrVal(p.Id),
			Name:        p.Name,
			Description: getStringPtrVal(p.Description),
			Status:      getStringPtrVal(p.Status),
			Priority:    getInt32PtrVal(p.Priority),
			System:      getBoolPtrVal(p.System),
			Type:        p.Type,
			Created:     p.Created,
			LastUpdated: p.LastUpdated,
			Settings:    p.Settings,
			Conditions:  nil, // PasswordPolicyConditions can't be cast to PolicyRuleConditions
		}
	case *okta.AuthenticatorEnrollmentPolicy:
		return &PolicyStructure{
			Id:          getStringPtrVal(p.Id),
			Name:        p.Name,
			Description: getStringPtrVal(p.Description),
			Status:      getStringPtrVal(p.Status),
			Priority:    getInt32PtrVal(p.Priority),
			System:      getBoolPtrVal(p.System),
			Type:        p.Type,
			Created:     p.Created,
			LastUpdated: p.LastUpdated,
			Settings:    p.Settings,
			Conditions:  nil, // Different condition types
		}
	}
	return nil
}

// Helper functions for pointer dereference
func getStringPtrVal(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

func getInt32PtrVal(i *int32) int32 {
	if i != nil {
		return *i
	}
	return 0
}

func getBoolPtrVal(b *bool) bool {
	if b != nil {
		return *b
	}
	return false
}

// generic policy missing Settings field (kept for compatibility with existing code)
type PolicyStructure struct {
	Embedded    interface{}                `json:"_embedded,omitempty"`
	Links       interface{}                `json:"_links,omitempty"`
	Settings    interface{}                `json:"settings,omitempty"`
	Conditions  *okta.PolicyRuleConditions `json:"conditions,omitempty"`
	Created     *time.Time                 `json:"created,omitempty"`
	Description string                     `json:"description,omitempty"`
	Id          string                     `json:"id,omitempty"`
	LastUpdated *time.Time                 `json:"lastUpdated,omitempty"`
	Name        string                     `json:"name,omitempty"`
	Priority    int32                      `json:"priority,omitempty"`
	Status      string                     `json:"status,omitempty"`
	System      bool                       `json:"system,omitempty"`
	Type        string                     `json:"type,omitempty"`
}
