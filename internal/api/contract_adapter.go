package api

import (
	"net/http"

	"github.com/dokosoko/complicatedauth-backend/internal/contract"
)

// ContractAdapter makes every generated operation an explicit compile-time
// obligation while the Server retains its authorization middleware pipeline.
type ContractAdapter struct{ server *Server }

var _ contract.ServerInterface = (*ContractAdapter)(nil)

func (a *ContractAdapter) Live(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
func (a *ContractAdapter) Ready(w http.ResponseWriter, r *http.Request) { a.server.ready(w, r) }
func (a *ContractAdapter) ListTenantActivity(w http.ResponseWriter, r *http.Request, _ contract.ListTenantActivityParams) {
	a.server.listActivity(w, r)
}
func (a *ContractAdapter) Login(w http.ResponseWriter, r *http.Request, _ contract.LoginParams) {
	a.server.login(w, r)
}
func (a *ContractAdapter) Logout(w http.ResponseWriter, r *http.Request, _ contract.LogoutParams) {
	a.server.logout(w, r)
}
func (a *ContractAdapter) GetConsoleSession(w http.ResponseWriter, r *http.Request) {
	a.server.session(w, r)
}
func (a *ContractAdapter) Signup(w http.ResponseWriter, r *http.Request, _ contract.SignupParams) {
	a.server.signup(w, r)
}
func (a *ContractAdapter) ListProjects(w http.ResponseWriter, r *http.Request, _ contract.ListProjectsParams) {
	a.server.listProjects(w, r)
}
func (a *ContractAdapter) CreateProject(w http.ResponseWriter, r *http.Request, _ contract.CreateProjectParams) {
	a.server.createProject(w, r)
}
func (a *ContractAdapter) GetProject(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid) {
	setProjectPath(r, projectUID.String())
	a.server.getProjectHandler(w, r)
}
func (a *ContractAdapter) UpdateProject(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, _ contract.UpdateProjectParams) {
	setProjectPath(r, projectUID.String())
	a.server.updateProject(w, r)
}
func (a *ContractAdapter) ListProjectActivity(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, _ contract.ListProjectActivityParams) {
	setProjectPath(r, projectUID.String())
	a.server.listActivity(w, r)
}
func (a *ContractAdapter) ListApiKeys(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid) {
	setProjectPath(r, projectUID.String())
	a.server.listAPIKeys(w, r)
}
func (a *ContractAdapter) CreateApiKey(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, _ contract.CreateApiKeyParams) {
	setProjectPath(r, projectUID.String())
	a.server.createAPIKey(w, r)
}
func (a *ContractAdapter) RevokeApiKey(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, keyUID contract.KeyUid, _ contract.RevokeApiKeyParams) {
	setProjectPath(r, projectUID.String())
	r.SetPathValue("key_uid", keyUID.String())
	a.server.revokeAPIKey(w, r)
}
func (a *ContractAdapter) RenameApiKey(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, keyUID contract.KeyUid, _ contract.RenameApiKeyParams) {
	setProjectPath(r, projectUID.String())
	r.SetPathValue("key_uid", keyUID.String())
	a.server.renameAPIKey(w, r)
}
func (a *ContractAdapter) RotateApiKey(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, keyUID contract.KeyUid, _ contract.RotateApiKeyParams) {
	setProjectPath(r, projectUID.String())
	r.SetPathValue("key_uid", keyUID.String())
	a.server.rotateAPIKey(w, r)
}
func (a *ContractAdapter) ListOrigins(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid) {
	setProjectPath(r, projectUID.String())
	a.server.listOrigins(w, r)
}
func (a *ContractAdapter) CreateOrigin(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, _ contract.CreateOriginParams) {
	setProjectPath(r, projectUID.String())
	a.server.createOrigin(w, r)
}
func (a *ContractAdapter) DeleteOrigin(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, originUID contract.OriginUid, _ contract.DeleteOriginParams) {
	setProjectPath(r, projectUID.String())
	r.SetPathValue("origin_uid", originUID.String())
	a.server.deleteOrigin(w, r)
}
func (a *ContractAdapter) DeleteProjectUserBiometric(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, params contract.DeleteProjectUserBiometricParams) {
	setProjectPath(r, projectUID.String())
	r.Header.Set("X-ComplicatedAuth-Session", params.XComplicatedAuthSession)
	a.server.deleteBiometricEnrollment(w, r)
}
func (a *ContractAdapter) EnrollProjectUserBiometric(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, params contract.EnrollProjectUserBiometricParams) {
	setProjectPath(r, projectUID.String())
	r.Header.Set("X-ComplicatedAuth-Session", params.XComplicatedAuthSession)
	a.server.enrollBiometric(w, r)
}
func (a *ContractAdapter) BeginFidoEnrollment(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, params contract.BeginFidoEnrollmentParams) {
	setProjectPath(r, projectUID.String())
	r.Header.Set("X-ComplicatedAuth-Session", params.XComplicatedAuthSession)
	a.server.beginFidoEnrollment(w, r)
}
func (a *ContractAdapter) FinishFidoEnrollment(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, params contract.FinishFidoEnrollmentParams) {
	setProjectPath(r, projectUID.String())
	r.Header.Set("X-ComplicatedAuth-Session", params.XComplicatedAuthSession)
	a.server.finishFidoEnrollment(w, r)
}
func (a *ContractAdapter) VerifyProjectUserBiometricLogin(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, params contract.VerifyProjectUserBiometricLoginParams) {
	setProjectPath(r, projectUID.String())
	r.Header.Set("X-ComplicatedAuth-Login", params.XComplicatedAuthLogin)
	a.server.verifyBiometricLogin(w, r)
}
func (a *ContractAdapter) BeginProjectUserFidoLogin(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, params contract.BeginProjectUserFidoLoginParams) {
	setProjectPath(r, projectUID.String())
	r.Header.Set("X-ComplicatedAuth-Login", params.XComplicatedAuthLogin)
	a.server.beginFidoLogin(w, r)
}
func (a *ContractAdapter) FinishProjectUserFidoLogin(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, params contract.FinishProjectUserFidoLoginParams) {
	setProjectPath(r, projectUID.String())
	r.Header.Set("X-ComplicatedAuth-Login", params.XComplicatedAuthLogin)
	a.server.finishFidoLogin(w, r)
}
func (a *ContractAdapter) BeginFirstFidoEnrollment(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, params contract.BeginFirstFidoEnrollmentParams) {
	setProjectPath(r, projectUID.String())
	r.Header.Set("X-ComplicatedAuth-Login", params.XComplicatedAuthLogin)
	a.server.beginFirstFidoEnrollment(w, r)
}
func (a *ContractAdapter) FinishFirstFidoEnrollment(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, params contract.FinishFirstFidoEnrollmentParams) {
	setProjectPath(r, projectUID.String())
	r.Header.Set("X-ComplicatedAuth-Login", params.XComplicatedAuthLogin)
	a.server.finishFirstFidoEnrollment(w, r)
}
func (a *ContractAdapter) VerifyProjectUserLoginPassword(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, params contract.VerifyProjectUserLoginPasswordParams) {
	setProjectPath(r, projectUID.String())
	r.Header.Set("X-ComplicatedAuth-Login", params.XComplicatedAuthLogin)
	a.server.verifyProjectUserLoginPassword(w, r)
}
func (a *ContractAdapter) StartProjectUserLogin(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid) {
	setProjectPath(r, projectUID.String())
	a.server.startProjectUserLogin(w, r)
}
func (a *ContractAdapter) IntrospectProjectUserSession(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid) {
	setProjectPath(r, projectUID.String())
	a.server.runtimeIntrospect(w, r)
}
func (a *ContractAdapter) RevokeProjectUserSession(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid) {
	setProjectPath(r, projectUID.String())
	a.server.runtimeRevoke(w, r)
}
func (a *ContractAdapter) ListProjectUsers(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, _ contract.ListProjectUsersParams) {
	setProjectPath(r, projectUID.String())
	a.server.listProjectUsers(w, r)
}
func (a *ContractAdapter) CreateProjectUser(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid) {
	setProjectPath(r, projectUID.String())
	a.server.createProjectUser(w, r)
}
func (a *ContractAdapter) GetProjectUser(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, userUID contract.UserUid) {
	setProjectUserPath(r, projectUID.String(), userUID.String())
	a.server.getProjectUserHandler(w, r)
}
func (a *ContractAdapter) UpdateProjectUser(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, userUID contract.UserUid, _ contract.UpdateProjectUserParams) {
	setProjectUserPath(r, projectUID.String(), userUID.String())
	a.server.updateProjectUser(w, r)
}
func (a *ContractAdapter) DeletePasskey(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, userUID contract.UserUid, credentialUID contract.CredentialUid) {
	setProjectUserPath(r, projectUID.String(), userUID.String())
	r.SetPathValue("credential_uid", credentialUID.String())
	a.server.deletePasskey(w, r)
}
func (a *ContractAdapter) ReplaceProjectUserPassword(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, userUID contract.UserUid) {
	setProjectUserPath(r, projectUID.String(), userUID.String())
	a.server.replaceProjectUserPassword(w, r)
}
func (a *ContractAdapter) RevokeProjectUserSessions(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, userUID contract.UserUid) {
	setProjectUserPath(r, projectUID.String(), userUID.String())
	a.server.revokeProjectUserSessions(w, r)
}

func setProjectPath(r *http.Request, projectUID string) { r.SetPathValue("project_uid", projectUID) }
func setProjectUserPath(r *http.Request, projectUID, userUID string) {
	setProjectPath(r, projectUID)
	r.SetPathValue("user_uid", userUID)
}
