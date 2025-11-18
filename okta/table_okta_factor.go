package okta

import (
	"context"
	"slices"
	"strings"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"github.com/turbot/go-kit/types"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"

	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

//// TABLE DEFINITION

func tableOktaFactor() *plugin.Table {
	return &plugin.Table{
		Name:        "okta_factor",
		Description: "Represents an Okta Factor.",
		Get: &plugin.GetConfig{
			Hydrate:           getOktaFactor,
			KeyColumns:        plugin.AllColumns([]string{"id", "user_id"}),
			ShouldIgnoreError: isNotFoundError([]string{"Not found", "Invalid Factor"}),
		},
		List: &plugin.ListConfig{
			ParentHydrate: listOktaUsers,
			Hydrate:       listOktaFactors,
			KeyColumns: []*plugin.KeyColumn{
				{Name: "user_id", Require: plugin.Optional},
			},
		},
		Columns: commonColumns([]*plugin.Column{
			// Top Columns
			{Name: "id", Type: proto.ColumnType_STRING, Description: "Unique key for Group.", Transform: transform.FromField("Factor.Id")},
			{Name: "user_id", Type: proto.ColumnType_STRING, Description: "Unique key for Group."},
			{Name: "user_name", Type: proto.ColumnType_STRING, Description: "Unique identifier for the user (username)."},
			{Name: "factor_type", Type: proto.ColumnType_STRING, Description: "Description of the Group.", Transform: transform.FromField("Factor.FactorType")},
			{Name: "created", Type: proto.ColumnType_TIMESTAMP, Description: "Timestamp when Group was created.", Transform: transform.FromField("Factor.Created")},

			// Other Columns
			{Name: "last_updated", Type: proto.ColumnType_TIMESTAMP, Description: "The timestamp when the factor was last updated.", Transform: transform.FromField("Factor.LastUpdated")},
			{Name: "provider", Type: proto.ColumnType_STRING, Description: "The provider for the factor.", Transform: transform.FromField("Factor.Provider")},
			{Name: "status", Type: proto.ColumnType_STRING, Description: "The current status of the factor.", Transform: transform.FromField("Factor.Status")},

			// JSON Columns
			{Name: "profile", Type: proto.ColumnType_JSON, Description: "Specific attributes related to the Factor.", Transform: transform.FromField("Factor.Profile")},
			{Name: "embedded", Type: proto.ColumnType_JSON, Description: "The Group's Profile properties.", Transform: transform.FromField("Factor.Embedded")},
			{Name: "verify", Type: proto.ColumnType_JSON, Description: "List of all users that are a member of this Group.", Transform: transform.FromField("Factor.Verify")},

			// Steampipe Columns
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Factor.Id"), Description: titleDescription},
		}),
	}
}

type UserFactorInfo struct {
	UserId   string
	UserName string
	Factor   OktaFactor
}

type OktaFactor struct {
	okta.UserFactor
	Profile interface{}
}

//// LIST FUNCTION

func listOktaFactors(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	client, err := Connect(ctx, d)
	if err != nil {
		logger.Error("okta_factor.listOktaFactors", "connect_error", err)
		return nil, err
	}

	var userId string
	var userName string
	if h.Item != nil {
		userData := h.Item.(*okta.User)
		userId = *userData.Id
		userName = userData.Profile.GetLogin()
	}

	// Minimize the API call with the given user id
	if d.EqualsQuals["user_id"] != nil {
		if d.EqualsQualString("user_id") != "" {
			if d.EqualsQualString("user_id") != "" && d.EqualsQualString("user_id") != userId {
				return nil, nil
			}
		} else if len(getListValues(d.EqualsQuals["user_id"].GetListValue())) > 0 {
			if !slices.Contains(types.StringValueSlice(getListValues(d.EqualsQuals["user_id"].GetListValue())), userId) {
				return nil, nil
			}
		}
	}

	if userId == "" {
		return nil, nil
	}

	factorReq := client.UserFactorAPI.ListFactors(ctx, userId)

	factors, resp, err := factorReq.Execute()
	if err != nil {
		logger.Error("okta_factor.listOktaFactors", "api_error", err)
		if strings.Contains(err.Error(), "Not found") {
			return nil, nil
		}
		return nil, err
	}

	for _, factor := range factors {
		if factor.GetActualInstance() != nil {
			factorDetails := getFactorDetails(factor.GetActualInstance())
			d.StreamListItem(ctx, UserFactorInfo{
				UserId:   userId,
				UserName: userName,
				Factor:   factorDetails,
			})

			// Context can be cancelled due to manual cancellation or the limit has been hit
			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}

	// paging
	for resp.HasNextPage() {
		var nextFactorSet []okta.ListFactors200ResponseInner
		resp, err = resp.Next(&nextFactorSet)
		if err != nil {
			logger.Error("okta_factor.listOktaFactors", "api_paging_error", err)
			return nil, err
		}

		for _, factor := range nextFactorSet {
			if factor.GetActualInstance() != nil {
				f := getFactorDetails(factor.GetActualInstance())
				d.StreamListItem(ctx, UserFactorInfo{
					UserId:   userId,
					UserName: userName,
					Factor:   f,
				})

				// Context can be cancelled due to manual cancellation or the limit has been hit
				if d.RowsRemaining(ctx) == 0 {
					return nil, nil
				}
			}
		}
	}

	return nil, err
}

//// HYDRATE FUNCTIONS

func getOktaFactor(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	userId := d.EqualsQuals["user_id"].GetStringValue()
	factorId := d.EqualsQuals["id"].GetStringValue()

	if userId == "" || factorId == "" {
		return nil, nil
	}

	client, err := Connect(ctx, d)
	if err != nil {
		logger.Error("okta_factor.getOktaFactor", "connection_error", err)
		return nil, err
	}

	userReq := client.UserAPI.GetUser(ctx, userId)
	user, _, err := userReq.Execute()
	if err != nil {
		logger.Error("okta_factor.getOktaFactor", "GetUser", err)
		if strings.Contains(err.Error(), "Not found") {
			return nil, nil
		}
		return nil, err
	}

	userProfile := *user.Profile
	userName := userProfile.Login

	factorReq := client.UserFactorAPI.GetFactor(ctx, userId, factorId)
	result, _, err := factorReq.Execute()
	if err != nil {
		logger.Error("okta_factor.getOktaFactor", "api_error", err)
		return nil, err
	}

	if result == nil {
		return nil, nil
	}
	f := OktaFactor{
		UserFactor: *result,
		Profile:    result.Profile,
	}

	return &UserFactorInfo{UserId: userId, UserName: *userName, Factor: f}, nil
}

//// UTILITY FUNCTION

func getFactorDetails(factor interface{}) OktaFactor {
	// In v6, different factor types have embedded UserFactor and their own Profile
	switch f := factor.(type) {
	case *okta.UserFactorCall:
		return OktaFactor{
			UserFactor: f.UserFactor,
			Profile:    f.Profile,
		}
	case *okta.UserFactorEmail:
		return OktaFactor{
			UserFactor: f.UserFactor,
			Profile:    f.Profile,
		}
	case *okta.UserFactorPush:
		return OktaFactor{
			UserFactor: f.UserFactor,
			Profile:    f.Profile,
		}
	case *okta.UserFactorSMS:
		return OktaFactor{
			UserFactor: f.UserFactor,
			Profile:    f.Profile,
		}
	case *okta.UserFactorSecurityQuestion:
		return OktaFactor{
			UserFactor: f.UserFactor,
			Profile:    f.Profile,
		}
	case *okta.UserFactorToken:
		return OktaFactor{
			UserFactor: f.UserFactor,
			Profile:    f.Profile,
		}
	case *okta.UserFactorTokenHOTP:
		return OktaFactor{
			UserFactor: f.UserFactor,
			Profile:    f.Profile,
		}
	case *okta.UserFactorTokenHardware:
		return OktaFactor{
			UserFactor: f.UserFactor,
			Profile:    f.Profile,
		}
	case *okta.UserFactorTokenSoftwareTOTP:
		return OktaFactor{
			UserFactor: f.UserFactor,
			Profile:    f.Profile,
		}
	case *okta.UserFactorU2F:
		return OktaFactor{
			UserFactor: f.UserFactor,
			Profile:    f.Profile,
		}
	case *okta.UserFactorWeb:
		return OktaFactor{
			UserFactor: f.UserFactor,
			Profile:    f.Profile,
		}
	case *okta.UserFactorWebAuthn:
		return OktaFactor{
			UserFactor: f.UserFactor,
			Profile:    f.Profile,
		}
	case *okta.UserFactor:
		return OktaFactor{
			UserFactor: *f,
			Profile:    f.GetProfile(),
		}
	case okta.UserFactor:
		return OktaFactor{
			UserFactor: f,
			Profile:    f.GetProfile(),
		}
	}
	return OktaFactor{}
}
