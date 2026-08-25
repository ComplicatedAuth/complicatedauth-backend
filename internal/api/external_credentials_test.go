package api

import (
	"reflect"
	"testing"
)

func TestExternalCredentialScopesExcludeManagementAndHonorSubsets(t *testing.T) {
	accountScopes := []string{
		serviceScopeProjectUsersRead,
		serviceScopeSupportCasesWrite,
		serviceScopeExternalCredentialsManage,
	}
	all, err := externalCredentialScopes(nil, accountScopes)
	if err != nil {
		t.Fatal(err)
	}
	wantAll := []string{serviceScopeProjectUsersRead, serviceScopeSupportCasesWrite}
	if !reflect.DeepEqual(all, wantAll) {
		t.Fatalf("default delegated scopes=%v want=%v", all, wantAll)
	}
	subset, err := externalCredentialScopes([]string{serviceScopeSupportCasesWrite}, accountScopes)
	if err != nil || !reflect.DeepEqual(subset, []string{serviceScopeSupportCasesWrite}) {
		t.Fatalf("delegated subset=%v err=%v", subset, err)
	}
	for _, invalid := range [][]string{{serviceScopeExternalCredentialsManage}, {serviceScopeSessionsManage}} {
		if _, err = externalCredentialScopes(invalid, accountScopes); err == nil {
			t.Fatalf("non-delegable scopes %v were accepted", invalid)
		}
	}
}

func TestNormalizeExternalCredentialIssueEnforcesConnectionScope(t *testing.T) {
	valid := externalCredentialIssueInput{
		DeploymentID: "deployment_acceptance", IntegrationID: "customer-api-v1",
		EnvironmentID: "sandbox", Subject: "ca_sub_pairwise",
		IdempotencyKey: "external_credential_123", TTLSeconds: 3600,
	}
	if err := normalizeExternalCredentialIssue(&valid); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	invalidInstance := valid
	invalidInstance.AccessInstanceID = "provider-instance"
	if err := normalizeExternalCredentialIssue(&invalidInstance); err == nil {
		t.Fatal("instance-scoped credential request was accepted")
	}
	invalidTTL := valid
	invalidTTL.TTLSeconds = 299
	if err := normalizeExternalCredentialIssue(&invalidTTL); err == nil {
		t.Fatal("sub-minimum credential TTL was accepted")
	}
}
