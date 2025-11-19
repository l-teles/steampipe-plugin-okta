package okta

import (
	"context"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"

	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

//// TABLE DEFINITION

func tableOktaApplicationAssignedUser() *plugin.Table {
	return &plugin.Table{
		Name:        "okta_app_assigned_user",
		Description: "Represents all assigned users for applications.",
		Get: &plugin.GetConfig{
			Hydrate:           getApplicationAssignedUser,
			KeyColumns:        plugin.AllColumns([]string{"id", "app_id"}),
			ShouldIgnoreError: isNotFoundError([]string{"Not found"}),
		},
		List: &plugin.ListConfig{
			ParentHydrate: getOrListOktaApplications,
			Hydrate:       listApplicationAssignedUsers,
			KeyColumns: plugin.KeyColumnSlice{
				{Name: "app_id", Require: plugin.Optional},
				{Name: "user_name", Require: plugin.Optional},
				{Name: "first_name", Require: plugin.Optional},
				{Name: "email", Require: plugin.Optional},
			},
		},

		Columns: commonColumns([]*plugin.Column{
			// Top Columns
			{Name: "id", Type: proto.ColumnType_STRING, Description: "Unique key for the application user."},
			{Name: "user_name", Type: proto.ColumnType_STRING, Transform: transform.FromField("Credentials.UserName"), Description: "The username of the application user."},
			{Name: "app_id", Type: proto.ColumnType_STRING, Description: "Unique key for the application."},
			{Name: "created", Type: proto.ColumnType_TIMESTAMP, Description: "Timestamp when application user was last updated."},
			{Name: "status", Type: proto.ColumnType_STRING, Description: "The status of the application user."},

			// Other Columns
			{Name: "email", Type: proto.ColumnType_STRING, Transform: transform.FromField("Profile.email"), Description: "The email of the application user."},
			{Name: "external_id", Type: proto.ColumnType_STRING, Description: "The external ID of the application user."},
			{Name: "first_name", Type: proto.ColumnType_STRING, Transform: transform.FromField("Profile.given_name"), Description: "The first name of the application user."},
			{Name: "last_name", Type: proto.ColumnType_STRING, Transform: transform.FromField("Profile.family_name"), Description: "The last name of the application user."},
			{Name: "last_sync", Type: proto.ColumnType_TIMESTAMP, Description: "Timestamp when application user was last synced."},
			{Name: "last_updated", Type: proto.ColumnType_TIMESTAMP, Description: "Timestamp when application user was last updated."},
			{Name: "password_changed", Type: proto.ColumnType_TIMESTAMP, Description: "Timestamp when application user's password was last changed."},
			{Name: "scope", Type: proto.ColumnType_STRING, Description: "The scope of the application user."},
			{Name: "status_changed", Type: proto.ColumnType_TIMESTAMP, Description: "Timestamp when application user's status was last changed."},
			{Name: "sync_state", Type: proto.ColumnType_STRING, Description: "The sync state of the application user."},

			// JSON Columns
			{Name: "links", Type: proto.ColumnType_JSON, Description: "The link details of the application user."},
			{Name: "profile", Type: proto.ColumnType_JSON, Description: "The profile details of the application user."},

			// Steampipe Columns
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Id"), Description: titleDescription},
		}),
	}
}

type AppUserInfo struct {
	AppId string
	okta.AppUser
}

//// LIST FUNCTION

func listApplicationAssignedUsers(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("listApplicationAssignedUsers")
	
	// Extract appId from union type
	var appId string
	switch item := h.Item.(type) {
	case okta.ListApplications200ResponseInner:
		if actual := item.GetActualInstance(); actual != nil {
			// Try to get ID from different application types
			switch app := actual.(type) {
			case *okta.AutoLoginApplication:
				if app.Id != nil {
					appId = *app.Id
				}
			case *okta.BasicAuthApplication:
				if app.Id != nil {
					appId = *app.Id
				}
			case *okta.BookmarkApplication:
				if app.Id != nil {
					appId = *app.Id
				}
			case *okta.BrowserPluginApplication:
				if app.Id != nil {
					appId = *app.Id
				}
			case *okta.OpenIdConnectApplication:
				if app.Id != nil {
					appId = *app.Id
				}
			case *okta.SamlApplication:
				if app.Id != nil {
					appId = *app.Id
				}
			case *okta.Saml11Application:
				if app.Id != nil {
					appId = *app.Id
				}
			case *okta.SecurePasswordStoreApplication:
				if app.Id != nil {
					appId = *app.Id
				}
			case *okta.WsFederationApplication:
				if app.Id != nil {
					appId = *app.Id
				}
			}
		}
	}

	if appId == "" {
		return nil, nil
	}

	client, err := Connect(ctx, d)
	if err != nil {
		logger.Error("listApplicationAssignedUsers", "connect_error", err)
		return nil, err
	}

	// Default maximum limit set as per documentation
	// https://developer.okta.com/docs/reference/api/apps/#list-users-assigned-to-application
	maxLimit := int64(500)

	var q string
	if d.EqualsQualString("user_name") != "" {
		q = d.EqualsQualString("user_name")
	} else if d.EqualsQualString("first_name") != "" {
		q = d.EqualsQualString("first_name")
	} else if d.EqualsQualString("email") != "" {
		q = d.EqualsQualString("email")
	}

	// If the requested number of items is less than the paging max limit
	// set the limit to that instead
	limit := d.QueryContext.Limit
	if d.QueryContext.Limit != nil {
		if *limit < maxLimit {
			maxLimit = *limit
		}
	}

	req := client.ApplicationUsersAPI.ListApplicationUsers(ctx, appId).Limit(int32(maxLimit))
	if q != "" {
		req = req.Q(q)
	}
	users, resp, err := req.Execute()

	if err != nil {
		logger.Error("listApplicationAssignedUsers", "list_app_users_error", err)
		return nil, err
	}

	for _, user := range users {
		d.StreamListItem(ctx, AppUserInfo{appId, user})

		// Context can be cancelled due to manual cancellation or the limit has been hit
		if d.RowsRemaining(ctx) == 0 {
			return nil, nil
		}
	}

	// paging
	for resp.HasNextPage() {
		var nextUserSet []okta.AppUser
		resp, err = resp.Next(&nextUserSet)
		if err != nil {
			logger.Error("listApplicationAssignedUsers", "list_app_users_paging_error", err)
			return nil, err
		}
		for _, user := range nextUserSet {
			d.StreamListItem(ctx, AppUserInfo{appId, user})

			// Context can be cancelled due to manual cancellation or the limit has been hit
			if d.RowsRemaining(ctx) == 0 {
				return nil, nil
			}
		}
	}

	return nil, nil
}

//// HYDRATE FUNCTION

func getApplicationAssignedUser(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	logger := plugin.Logger(ctx)
	logger.Trace("getApplicationAssignedUser")
	appId := d.EqualsQuals["app_id"].GetStringValue()
	userId := d.EqualsQuals["id"].GetStringValue()

	if appId == "" || userId == "" {
		return nil, nil
	}

	client, err := Connect(ctx, d)
	if err != nil {
		logger.Error("getApplicationAssignedUser", "connect_error", err)
		return nil, err
	}

	user, _, err := client.ApplicationUsersAPI.GetApplicationUser(ctx, appId, userId).Execute()
	if err != nil {
		logger.Error("getApplicationAssignedUser", "get_app_user_error", err)
		return nil, err
	}

	return AppUserInfo{appId, *user}, nil
}
