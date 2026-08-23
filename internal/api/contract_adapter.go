package api

import (
	"net/http"

	"github.com/complicatedauth/complicatedauth-backend/internal/contract"
)

// ContractAdapter makes every generated operation an explicit compile-time
// obligation while the Server retains its authorization middleware pipeline.
type ContractAdapter struct{ server *Server }

var _ contract.ServerInterface = (*ContractAdapter)(nil)

func (a *ContractAdapter) Live(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
func (a *ContractAdapter) Ready(w http.ResponseWriter, r *http.Request) { a.server.ready(w, r) }
func (a *ContractAdapter) GetOpenIdConfiguration(w http.ResponseWriter, r *http.Request) {
	a.server.oidcDiscovery(w, r)
}
func (a *ContractAdapter) AuthorizeOAuthApplication(w http.ResponseWriter, r *http.Request, _ contract.AuthorizeOAuthApplicationParams) {
	a.server.oauthAuthorize(w, r)
}
func (a *ContractAdapter) GetOAuthJwks(w http.ResponseWriter, r *http.Request) {
	a.server.oauthJWKS(w, r)
}
func (a *ContractAdapter) RevokeOAuthToken(w http.ResponseWriter, r *http.Request) {
	a.server.oauthRevoke(w, r)
}
func (a *ContractAdapter) ExchangeOAuthAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	a.server.oauthToken(w, r)
}
func (a *ContractAdapter) GetOAuthUserInfo(w http.ResponseWriter, r *http.Request) {
	a.server.oauthUserInfo(w, r)
}
func (a *ContractAdapter) ListOAuthApplications(w http.ResponseWriter, r *http.Request, _ contract.ListOAuthApplicationsParams) {
	a.server.listOAuthApplications(w, r)
}
func (a *ContractAdapter) CreateOAuthApplication(w http.ResponseWriter, r *http.Request, _ contract.CreateOAuthApplicationParams) {
	a.server.createOAuthApplication(w, r)
}
func (a *ContractAdapter) GetOAuthApplication(w http.ResponseWriter, r *http.Request, applicationUID contract.OAuthApplicationUid) {
	r.SetPathValue("application_uid", applicationUID.String())
	a.server.getOAuthApplication(w, r)
}
func (a *ContractAdapter) UpdateOAuthApplication(w http.ResponseWriter, r *http.Request, applicationUID contract.OAuthApplicationUid, _ contract.UpdateOAuthApplicationParams) {
	r.SetPathValue("application_uid", applicationUID.String())
	a.server.updateOAuthApplication(w, r)
}
func (a *ContractAdapter) DeleteOAuthApplication(w http.ResponseWriter, r *http.Request, applicationUID contract.OAuthApplicationUid, _ contract.DeleteOAuthApplicationParams) {
	r.SetPathValue("application_uid", applicationUID.String())
	a.server.deleteOAuthApplication(w, r)
}
func (a *ContractAdapter) ListOAuthClientSecrets(w http.ResponseWriter, r *http.Request, applicationUID contract.OAuthApplicationUid) {
	r.SetPathValue("application_uid", applicationUID.String())
	a.server.listOAuthClientSecrets(w, r)
}
func (a *ContractAdapter) CreateOAuthClientSecret(w http.ResponseWriter, r *http.Request, applicationUID contract.OAuthApplicationUid, _ contract.CreateOAuthClientSecretParams) {
	r.SetPathValue("application_uid", applicationUID.String())
	a.server.createOAuthClientSecret(w, r)
}
func (a *ContractAdapter) RevokeOAuthClientSecret(w http.ResponseWriter, r *http.Request, applicationUID contract.OAuthApplicationUid, secretUID contract.OAuthClientSecretUid, _ contract.RevokeOAuthClientSecretParams) {
	r.SetPathValue("application_uid", applicationUID.String())
	r.SetPathValue("secret_uid", secretUID.String())
	a.server.revokeOAuthClientSecret(w, r)
}
func (a *ContractAdapter) InspectOAuthAuthorizationRequest(w http.ResponseWriter, r *http.Request, _ contract.InspectOAuthAuthorizationRequestParams) {
	a.server.inspectOAuthAuthorizationRequest(w, r)
}
func (a *ContractAdapter) DecideOAuthAuthorizationRequest(w http.ResponseWriter, r *http.Request, _ contract.DecideOAuthAuthorizationRequestParams) {
	a.server.decideOAuthAuthorizationRequest(w, r)
}
func (a *ContractAdapter) ListOAuthConsents(w http.ResponseWriter, r *http.Request, _ contract.ListOAuthConsentsParams) {
	a.server.listOAuthConsents(w, r)
}
func (a *ContractAdapter) RevokeOAuthConsent(w http.ResponseWriter, r *http.Request, consentUID contract.OAuthConsentUid, _ contract.RevokeOAuthConsentParams) {
	r.SetPathValue("consent_uid", consentUID.String())
	a.server.revokeOAuthConsent(w, r)
}
func (a *ContractAdapter) CreateAuthorizationDecision(w http.ResponseWriter, r *http.Request) {
	a.server.createAuthorizationDecision(w, r)
}
func (a *ContractAdapter) ListOAuthApplicationGrants(w http.ResponseWriter, r *http.Request, applicationUID contract.OAuthApplicationUid) {
	r.SetPathValue("application_uid", applicationUID.String())
	a.server.listOAuthApplicationGrants(w, r)
}
func (a *ContractAdapter) CreateOAuthApplicationGrant(w http.ResponseWriter, r *http.Request, applicationUID contract.OAuthApplicationUid, _ contract.CreateOAuthApplicationGrantParams) {
	r.SetPathValue("application_uid", applicationUID.String())
	a.server.createOAuthApplicationGrant(w, r)
}
func (a *ContractAdapter) GetOAuthApplicationGrant(w http.ResponseWriter, r *http.Request, applicationUID contract.OAuthApplicationUid, grantUID contract.OAuthApplicationGrantUid) {
	r.SetPathValue("application_uid", applicationUID.String())
	r.SetPathValue("grant_uid", grantUID.String())
	a.server.getOAuthApplicationGrant(w, r)
}
func (a *ContractAdapter) UpdateOAuthApplicationGrant(w http.ResponseWriter, r *http.Request, applicationUID contract.OAuthApplicationUid, grantUID contract.OAuthApplicationGrantUid, _ contract.UpdateOAuthApplicationGrantParams) {
	r.SetPathValue("application_uid", applicationUID.String())
	r.SetPathValue("grant_uid", grantUID.String())
	a.server.updateOAuthApplicationGrant(w, r)
}
func (a *ContractAdapter) DeleteOAuthApplicationGrant(w http.ResponseWriter, r *http.Request, applicationUID contract.OAuthApplicationUid, grantUID contract.OAuthApplicationGrantUid, _ contract.DeleteOAuthApplicationGrantParams) {
	r.SetPathValue("application_uid", applicationUID.String())
	r.SetPathValue("grant_uid", grantUID.String())
	a.server.deleteOAuthApplicationGrant(w, r)
}
func (a *ContractAdapter) ListTenantActivity(w http.ResponseWriter, r *http.Request, _ contract.ListTenantActivityParams) {
	a.server.listActivity(w, r)
}
func (a *ContractAdapter) Logout(w http.ResponseWriter, r *http.Request, _ contract.LogoutParams) {
	a.server.logout(w, r)
}
func (a *ContractAdapter) GetConsoleSession(w http.ResponseWriter, r *http.Request) {
	a.server.session(w, r)
}
func (a *ContractAdapter) ListTenantMemberSessions(w http.ResponseWriter, r *http.Request, _ contract.ListTenantMemberSessionsParams) {
	a.server.listMemberSessions(w, r)
}
func (a *ContractAdapter) RevokeTenantMemberSession(w http.ResponseWriter, r *http.Request, sessionUID contract.MemberSessionUid, _ contract.RevokeTenantMemberSessionParams) {
	r.SetPathValue("session_uid", sessionUID.String())
	a.server.revokeMemberSession(w, r)
}
func (a *ContractAdapter) Signup(w http.ResponseWriter, r *http.Request, _ contract.SignupParams) {
	a.server.signup(w, r)
}
func (a *ContractAdapter) CreateTenantEmailVerificationRequest(w http.ResponseWriter, r *http.Request, _ contract.CreateTenantEmailVerificationRequestParams) {
	a.server.createTenantEmailVerificationRequest(w, r)
}
func (a *ContractAdapter) VerifyTenantMemberEmail(w http.ResponseWriter, r *http.Request, _ contract.VerifyTenantMemberEmailParams) {
	a.server.verifyTenantEmail(w, r)
}
func (a *ContractAdapter) CreateTenantMemberLoginAttempt(w http.ResponseWriter, r *http.Request, _ contract.CreateTenantMemberLoginAttemptParams) {
	a.server.createTenantMemberLoginAttempt(w, r)
}
func (a *ContractAdapter) VerifyTenantMemberLoginPassword(w http.ResponseWriter, r *http.Request, loginAttemptUID contract.LoginAttemptUid, _ contract.VerifyTenantMemberLoginPasswordParams) {
	r.SetPathValue("login_attempt_uid", loginAttemptUID.String())
	a.server.verifyTenantMemberLoginPassword(w, r)
}
func (a *ContractAdapter) CreateTenantMemberWebAuthnAuthenticationCeremony(w http.ResponseWriter, r *http.Request, loginAttemptUID contract.LoginAttemptUid, _ contract.CreateTenantMemberWebAuthnAuthenticationCeremonyParams) {
	r.SetPathValue("login_attempt_uid", loginAttemptUID.String())
	a.server.beginTenantMemberWebAuthnLogin(w, r)
}
func (a *ContractAdapter) VerifyTenantMemberWebAuthnAuthentication(w http.ResponseWriter, r *http.Request, loginAttemptUID contract.LoginAttemptUid, _ contract.VerifyTenantMemberWebAuthnAuthenticationParams) {
	r.SetPathValue("login_attempt_uid", loginAttemptUID.String())
	a.server.finishTenantMemberWebAuthnLogin(w, r)
}
func (a *ContractAdapter) CreateInitialTenantMemberWebAuthnRegistrationCeremony(w http.ResponseWriter, r *http.Request, loginAttemptUID contract.LoginAttemptUid, _ contract.CreateInitialTenantMemberWebAuthnRegistrationCeremonyParams) {
	r.SetPathValue("login_attempt_uid", loginAttemptUID.String())
	a.server.beginInitialTenantMemberWebAuthnEnrollment(w, r)
}
func (a *ContractAdapter) VerifyInitialTenantMemberWebAuthnRegistration(w http.ResponseWriter, r *http.Request, loginAttemptUID contract.LoginAttemptUid, _ contract.VerifyInitialTenantMemberWebAuthnRegistrationParams) {
	r.SetPathValue("login_attempt_uid", loginAttemptUID.String())
	a.server.finishInitialTenantMemberWebAuthnEnrollment(w, r)
}
func (a *ContractAdapter) CreateTenantPasswordResetRequest(w http.ResponseWriter, r *http.Request, _ contract.CreateTenantPasswordResetRequestParams) {
	a.server.createTenantPasswordResetRequest(w, r)
}
func (a *ContractAdapter) ResetTenantMemberPassword(w http.ResponseWriter, r *http.Request, _ contract.ResetTenantMemberPasswordParams) {
	a.server.resetTenantMemberPassword(w, r)
}
func (a *ContractAdapter) ListTenantMemberWebAuthnCredentials(w http.ResponseWriter, r *http.Request) {
	a.server.listTenantMemberWebAuthnCredentials(w, r)
}
func (a *ContractAdapter) CreateTenantMemberWebAuthnRegistrationCeremony(w http.ResponseWriter, r *http.Request, _ contract.CreateTenantMemberWebAuthnRegistrationCeremonyParams) {
	a.server.beginSessionTenantMemberWebAuthnEnrollment(w, r)
}
func (a *ContractAdapter) VerifyTenantMemberWebAuthnRegistration(w http.ResponseWriter, r *http.Request, _ contract.VerifyTenantMemberWebAuthnRegistrationParams) {
	a.server.finishSessionTenantMemberWebAuthnEnrollment(w, r)
}
func (a *ContractAdapter) UpdateTenantMemberWebAuthnCredential(w http.ResponseWriter, r *http.Request, credentialUID contract.TenantMemberWebAuthnCredentialUid, _ contract.UpdateTenantMemberWebAuthnCredentialParams) {
	r.SetPathValue("credential_uid", credentialUID.String())
	a.server.updateTenantMemberWebAuthnCredential(w, r)
}
func (a *ContractAdapter) DeleteTenantMemberWebAuthnCredential(w http.ResponseWriter, r *http.Request, credentialUID contract.TenantMemberWebAuthnCredentialUid, _ contract.DeleteTenantMemberWebAuthnCredentialParams) {
	r.SetPathValue("credential_uid", credentialUID.String())
	a.server.deleteTenantMemberWebAuthnCredential(w, r)
}
func (a *ContractAdapter) ListTenantMembers(w http.ResponseWriter, r *http.Request, _ contract.ListTenantMembersParams) {
	a.server.listTenantMembers(w, r)
}
func (a *ContractAdapter) GetTenantMember(w http.ResponseWriter, r *http.Request, memberUID contract.MemberUid) {
	r.SetPathValue("member_uid", memberUID.String())
	a.server.getTenantMember(w, r)
}
func (a *ContractAdapter) UpdateTenantMember(w http.ResponseWriter, r *http.Request, memberUID contract.MemberUid, _ contract.UpdateTenantMemberParams) {
	r.SetPathValue("member_uid", memberUID.String())
	a.server.updateTenantMember(w, r)
}
func (a *ContractAdapter) RemoveTenantMember(w http.ResponseWriter, r *http.Request, memberUID contract.MemberUid, _ contract.RemoveTenantMemberParams) {
	r.SetPathValue("member_uid", memberUID.String())
	a.server.removeTenantMember(w, r)
}
func (a *ContractAdapter) ListTenantInvitations(w http.ResponseWriter, r *http.Request, _ contract.ListTenantInvitationsParams) {
	a.server.listTenantInvitations(w, r)
}
func (a *ContractAdapter) CreateTenantInvitation(w http.ResponseWriter, r *http.Request, _ contract.CreateTenantInvitationParams) {
	a.server.createTenantInvitation(w, r)
}
func (a *ContractAdapter) RevokeTenantInvitation(w http.ResponseWriter, r *http.Request, invitationUID contract.InvitationUid, _ contract.RevokeTenantInvitationParams) {
	r.SetPathValue("invitation_uid", invitationUID.String())
	a.server.revokeTenantInvitation(w, r)
}
func (a *ContractAdapter) AcceptTenantInvitation(w http.ResponseWriter, r *http.Request, invitationUID contract.InvitationUid, _ contract.AcceptTenantInvitationParams) {
	r.SetPathValue("invitation_uid", invitationUID.String())
	a.server.acceptTenantInvitation(w, r)
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
func (a *ContractAdapter) ListServiceAccounts(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, _ contract.ListServiceAccountsParams) {
	setProjectPath(r, projectUID.String())
	a.server.listServiceAccounts(w, r)
}
func (a *ContractAdapter) CreateServiceAccount(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, _ contract.CreateServiceAccountParams) {
	setProjectPath(r, projectUID.String())
	a.server.createServiceAccount(w, r)
}
func (a *ContractAdapter) GetServiceAccount(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, accountUID contract.ServiceAccountUid) {
	setProjectPath(r, projectUID.String())
	r.SetPathValue("service_account_uid", accountUID.String())
	a.server.getServiceAccount(w, r)
}
func (a *ContractAdapter) UpdateServiceAccount(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, accountUID contract.ServiceAccountUid, _ contract.UpdateServiceAccountParams) {
	setProjectPath(r, projectUID.String())
	r.SetPathValue("service_account_uid", accountUID.String())
	a.server.updateServiceAccount(w, r)
}
func (a *ContractAdapter) DeleteServiceAccount(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, accountUID contract.ServiceAccountUid, _ contract.DeleteServiceAccountParams) {
	setProjectPath(r, projectUID.String())
	r.SetPathValue("service_account_uid", accountUID.String())
	a.server.deleteServiceAccount(w, r)
}
func (a *ContractAdapter) ListServiceCredentials(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, accountUID contract.ServiceAccountUid, _ contract.ListServiceCredentialsParams) {
	setProjectPath(r, projectUID.String())
	r.SetPathValue("service_account_uid", accountUID.String())
	a.server.listServiceCredentials(w, r)
}
func (a *ContractAdapter) CreateServiceCredential(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, accountUID contract.ServiceAccountUid, _ contract.CreateServiceCredentialParams) {
	setProjectPath(r, projectUID.String())
	r.SetPathValue("service_account_uid", accountUID.String())
	a.server.createServiceCredential(w, r)
}
func (a *ContractAdapter) GetServiceCredential(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, accountUID contract.ServiceAccountUid, credentialUID contract.ServiceCredentialUid) {
	setProjectPath(r, projectUID.String())
	r.SetPathValue("service_account_uid", accountUID.String())
	r.SetPathValue("credential_uid", credentialUID.String())
	a.server.getServiceCredential(w, r)
}
func (a *ContractAdapter) RevokeServiceCredential(w http.ResponseWriter, r *http.Request, projectUID contract.ProjectUid, accountUID contract.ServiceAccountUid, credentialUID contract.ServiceCredentialUid, _ contract.RevokeServiceCredentialParams) {
	setProjectPath(r, projectUID.String())
	r.SetPathValue("service_account_uid", accountUID.String())
	r.SetPathValue("credential_uid", credentialUID.String())
	a.server.revokeServiceCredential(w, r)
}
func (a *ContractAdapter) ListSupportCases(w http.ResponseWriter, r *http.Request, _ contract.ListSupportCasesParams) {
	a.server.listSupportCases(w, r)
}
func (a *ContractAdapter) CreateSupportCase(w http.ResponseWriter, r *http.Request, _ contract.CreateSupportCaseParams) {
	a.server.createSupportCase(w, r)
}
func (a *ContractAdapter) GetSupportCase(w http.ResponseWriter, r *http.Request, caseUID contract.SupportCaseUid) {
	r.SetPathValue("case_uid", caseUID.String())
	a.server.getSupportCase(w, r)
}
func (a *ContractAdapter) UpdateSupportCase(w http.ResponseWriter, r *http.Request, caseUID contract.SupportCaseUid, _ contract.UpdateSupportCaseParams) {
	r.SetPathValue("case_uid", caseUID.String())
	a.server.updateSupportCase(w, r)
}
func (a *ContractAdapter) ListSupportCaseMessages(w http.ResponseWriter, r *http.Request, caseUID contract.SupportCaseUid, _ contract.ListSupportCaseMessagesParams) {
	r.SetPathValue("case_uid", caseUID.String())
	a.server.listSupportCaseMessages(w, r)
}
func (a *ContractAdapter) CreateSupportCaseMessage(w http.ResponseWriter, r *http.Request, caseUID contract.SupportCaseUid, _ contract.CreateSupportCaseMessageParams) {
	r.SetPathValue("case_uid", caseUID.String())
	a.server.createSupportCaseMessage(w, r)
}
func (a *ContractAdapter) ListSupportCaseAttachments(w http.ResponseWriter, r *http.Request, caseUID contract.SupportCaseUid, _ contract.ListSupportCaseAttachmentsParams) {
	r.SetPathValue("case_uid", caseUID.String())
	a.server.listSupportCaseAttachments(w, r)
}
func (a *ContractAdapter) CreateSupportCaseAttachment(w http.ResponseWriter, r *http.Request, caseUID contract.SupportCaseUid, _ contract.CreateSupportCaseAttachmentParams) {
	r.SetPathValue("case_uid", caseUID.String())
	a.server.createSupportCaseAttachment(w, r)
}
func (a *ContractAdapter) GetSupportCaseAttachment(w http.ResponseWriter, r *http.Request, caseUID contract.SupportCaseUid, attachmentUID contract.SupportCaseAttachmentUid) {
	r.SetPathValue("case_uid", caseUID.String())
	r.SetPathValue("attachment_uid", attachmentUID.String())
	a.server.getSupportCaseAttachment(w, r)
}
func (a *ContractAdapter) DownloadSupportCaseAttachment(w http.ResponseWriter, r *http.Request, caseUID contract.SupportCaseUid, attachmentUID contract.SupportCaseAttachmentUid) {
	r.SetPathValue("case_uid", caseUID.String())
	r.SetPathValue("attachment_uid", attachmentUID.String())
	a.server.downloadSupportCaseAttachment(w, r)
}
func (a *ContractAdapter) ListSupportCaseEvents(w http.ResponseWriter, r *http.Request, caseUID contract.SupportCaseUid, _ contract.ListSupportCaseEventsParams) {
	r.SetPathValue("case_uid", caseUID.String())
	a.server.listSupportCaseEvents(w, r)
}
func (a *ContractAdapter) ListSupportCaseExternalReferences(w http.ResponseWriter, r *http.Request, caseUID contract.SupportCaseUid, _ contract.ListSupportCaseExternalReferencesParams) {
	r.SetPathValue("case_uid", caseUID.String())
	a.server.listSupportCaseExternalReferences(w, r)
}
func (a *ContractAdapter) CreateSupportCaseExternalReference(w http.ResponseWriter, r *http.Request, caseUID contract.SupportCaseUid, _ contract.CreateSupportCaseExternalReferenceParams) {
	r.SetPathValue("case_uid", caseUID.String())
	a.server.createSupportCaseExternalReference(w, r)
}
func (a *ContractAdapter) DeleteSupportCaseExternalReference(w http.ResponseWriter, r *http.Request, caseUID contract.SupportCaseUid, referenceUID contract.SupportCaseExternalReferenceUid, _ contract.DeleteSupportCaseExternalReferenceParams) {
	r.SetPathValue("case_uid", caseUID.String())
	r.SetPathValue("external_reference_uid", referenceUID.String())
	a.server.deleteSupportCaseExternalReference(w, r)
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

func (a *ContractAdapter) ListResourceServers(w http.ResponseWriter, r *http.Request, _ contract.ListResourceServersParams) {
	a.server.listResourceServers(w, r)
}
func (a *ContractAdapter) CreateResourceServer(w http.ResponseWriter, r *http.Request, _ contract.CreateResourceServerParams) {
	a.server.createResourceServer(w, r)
}
func (a *ContractAdapter) GetResourceServer(w http.ResponseWriter, r *http.Request, resourceServerUID contract.ResourceServerUid) {
	r.SetPathValue("resource_server_uid", resourceServerUID.String())
	a.server.getResourceServer(w, r)
}
func (a *ContractAdapter) UpdateResourceServer(w http.ResponseWriter, r *http.Request, resourceServerUID contract.ResourceServerUid, _ contract.UpdateResourceServerParams) {
	r.SetPathValue("resource_server_uid", resourceServerUID.String())
	a.server.updateResourceServer(w, r)
}
func (a *ContractAdapter) DeleteResourceServer(w http.ResponseWriter, r *http.Request, resourceServerUID contract.ResourceServerUid, _ contract.DeleteResourceServerParams) {
	r.SetPathValue("resource_server_uid", resourceServerUID.String())
	a.server.deleteResourceServer(w, r)
}
func (a *ContractAdapter) ListResourceServerScopes(w http.ResponseWriter, r *http.Request, resourceServerUID contract.ResourceServerUid) {
	r.SetPathValue("resource_server_uid", resourceServerUID.String())
	a.server.listResourceServerScopes(w, r)
}
func (a *ContractAdapter) CreateResourceServerScope(w http.ResponseWriter, r *http.Request, resourceServerUID contract.ResourceServerUid, _ contract.CreateResourceServerScopeParams) {
	r.SetPathValue("resource_server_uid", resourceServerUID.String())
	a.server.createResourceServerScope(w, r)
}
func (a *ContractAdapter) GetResourceServerScope(w http.ResponseWriter, r *http.Request, resourceServerUID contract.ResourceServerUid, scopeUID contract.ResourceServerScopeUid) {
	r.SetPathValue("resource_server_uid", resourceServerUID.String())
	r.SetPathValue("scope_uid", scopeUID.String())
	a.server.getResourceServerScope(w, r)
}
func (a *ContractAdapter) UpdateResourceServerScope(w http.ResponseWriter, r *http.Request, resourceServerUID contract.ResourceServerUid, scopeUID contract.ResourceServerScopeUid, _ contract.UpdateResourceServerScopeParams) {
	r.SetPathValue("resource_server_uid", resourceServerUID.String())
	r.SetPathValue("scope_uid", scopeUID.String())
	a.server.updateResourceServerScope(w, r)
}
func (a *ContractAdapter) DeleteResourceServerScope(w http.ResponseWriter, r *http.Request, resourceServerUID contract.ResourceServerUid, scopeUID contract.ResourceServerScopeUid, _ contract.DeleteResourceServerScopeParams) {
	r.SetPathValue("resource_server_uid", resourceServerUID.String())
	r.SetPathValue("scope_uid", scopeUID.String())
	a.server.deleteResourceServerScope(w, r)
}

func setProjectPath(r *http.Request, projectUID string) { r.SetPathValue("project_uid", projectUID) }
func setProjectUserPath(r *http.Request, projectUID, userUID string) {
	setProjectPath(r, projectUID)
	r.SetPathValue("user_uid", userUID)
}
