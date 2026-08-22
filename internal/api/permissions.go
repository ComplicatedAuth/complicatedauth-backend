package api

const (
	permissionRead                = "read"
	permissionManageTenant        = "tenant.manage"
	permissionManageProjects      = "projects.manage"
	permissionManageCredentials   = "credentials.manage"
	permissionManageUsers         = "project_users.manage"
	permissionSupportUsers        = "project_users.support"
	permissionManageOAuth         = "oauth.manage"
	permissionManageAuthorization = "authorization.manage"
	permissionManageSupport       = "support_cases.manage"
)

var permissionsByRole = map[string]map[string]bool{
	"owner": {
		permissionRead: true, permissionManageTenant: true, permissionManageProjects: true,
		permissionManageCredentials: true, permissionManageUsers: true, permissionSupportUsers: true,
		permissionManageOAuth: true, permissionManageAuthorization: true,
		permissionManageSupport: true,
	},
	"admin": {
		permissionRead: true, permissionManageTenant: true, permissionManageProjects: true,
		permissionManageCredentials: true, permissionManageUsers: true, permissionSupportUsers: true,
		permissionManageOAuth: true, permissionManageAuthorization: true,
		permissionManageSupport: true,
	},
	"developer": {
		permissionRead: true, permissionManageProjects: true, permissionManageCredentials: true,
		permissionManageUsers: true, permissionSupportUsers: true,
		permissionManageOAuth: true, permissionManageAuthorization: true,
	},
	"support": {permissionRead: true, permissionSupportUsers: true, permissionManageSupport: true},
	"viewer":  {permissionRead: true},
}

func roleAllows(role, permission string) bool {
	return permissionsByRole[role][permission]
}
