// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

// These exact test IDs have separate, explicit fixture owners. This is
// a reviewed catalog, not a pattern or a list learned from a running test suite.
// A renamed/new skipped test fails accounting until deliberately reviewed.
type optionalAcceptance struct{ Package, Test, Flag, Profile string }

var optionalAcceptanceCatalog = []optionalAcceptance{
	{"internal/handler", "TestRenderedCollabCanonicalSaveAndReloadE2E", "HASH_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestOwnedCommentHistoryPortalsWithExternalBrowserE2E", "HASH_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestCRMConnectionWithExternalBrowserE2E", "HASH_CRM_CONNECTION_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestCRMDocumentWithExternalBrowserE2E", "HASH_CRM_DOCUMENT_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestCRMTemplatePopulationWithExternalBrowserE2E", "HASH_CRM_TEMPLATE_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestRenderedDocumentNavigationKeepsNegotiationsScopedE2E", "HASH_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestDocumentPackageStaffEditorWithExternalBrowser228E2E", "HASH_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestRenderedDSRDeletedArchiveReviewE2E", "HASH_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestRenderedFieldDesignerMutationsStayScopedE2E", "HASH_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestRenderedHTMLDocumentRevisionWithExternalBrowserE2E", "HASH_HTML_REVISION_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestLaterAmendmentWholeSPABrowser487E2E", "HASH_AMENDMENT_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestRenderedNegotiationConversationE2E", "HASH_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestOrdinaryOIDCStaffPortalWithExternalBrowser439E2E", "HASH_OIDC_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestOwnedSignerNativePrefixCancelWithExternalBrowserE2E", "HASH_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestOwnedRealRenderedSignerFourArtifactsWithExternalBrowserE2E", "HASH_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestPublicNegotiatedPackageWithExternalBrowser403E2E", "HASH_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestPublicPackageFullCeremonyWithExternalBrowser256E2E", "HASH_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestPresignRegistrySettingsWithExternalBrowserE2E", "HASH_PRESIGN_REGISTRY_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestRenderedSenderPanelRecipientDraftsStayScopedE2E", "HASH_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestRealRenderedSignerPDFObservationWithExternalBrowserE2E", "HASH_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestOrdinaryOIDCSenderApprovedTemplateWithExternalBrowser444E2E", "HASH_TEMPLATE_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestOrdinaryOIDCTemplateSendCompleteWithExternalBrowser447E2E", "HASH_TEMPLATE_SEND_BROWSER_E2E", "external-browser"},
	{"internal/handler", "TestOwnedManualPDFRealObjectLockChromiumTwoSignAndFourArtifactsE2E", "HASH_PRESIGN_EXECUTION_E2E", "owned-provider-real-stack"},
	{"internal/handler", "TestPresign488ActualHTTPConcurrentReplayCustomerSignAndEvidenceE2E", "HASH_PRESIGN_EXECUTION_E2E", "owned-provider-real-stack"},
	{"internal/handler", "TestPresign488ActualHTTPSelectedAnnexDenialE2E", "HASH_PRESIGN_EXECUTION_E2E", "owned-provider-real-stack"},
	{"internal/handler", "TestPresign488ActualHTTPAPIPriorSupersessionAfterCompletionE2E", "HASH_PRESIGN_EXECUTION_E2E", "owned-provider-real-stack"},
	{"internal/sign", "TestFittedOutputJournalDurableOriginalAndSinglePutE2E", "HASH_E2E_FITTED_OUTPUT_OWNED_PG", "fitted-output"},
	{"internal/sign", "TestFittedOutputJournalPositivePinSurvivesLateProviderFailureE2E/late_error", "HASH_E2E_FITTED_OUTPUT_OWNED_PG", "fitted-output"},
	{"internal/sign", "TestFittedOutputJournalPositivePinSurvivesLateProviderFailureE2E/late_cancel", "HASH_E2E_FITTED_OUTPUT_OWNED_PG", "fitted-output"},
	{"internal/sign", "TestFittedOutputJournalPositivePinSurvivesLateProviderFailureE2E/late_resolver_error", "HASH_E2E_FITTED_OUTPUT_OWNED_PG", "fitted-output"},
	{"internal/sign", "TestFittedOutputJournalCurrentOwnerAndLeaseRefuseBeforeBodyE2E/different_owner", "HASH_E2E_FITTED_OUTPUT_OWNED_PG", "fitted-output"},
	{"internal/sign", "TestFittedOutputJournalCurrentOwnerAndLeaseRefuseBeforeBodyE2E/expired_then_taken_over", "HASH_E2E_FITTED_OUTPUT_OWNED_PG", "fitted-output"},
	{"internal/sign", "TestFittedOutputJournalBlockedCancellationPhysicallyJoinsE2E", "HASH_E2E_FITTED_OUTPUT_OWNED_PG", "fitted-output"},
	{"internal/sign", "TestFittedOutputJournalUnknownAttemptEmptyObservationNeverReuploadsE2E", "HASH_E2E_FITTED_OUTPUT_OWNED_PG", "fitted-output"},
	{"internal/sign", "TestFittedOutputJournalObservedVersionRequiresExactCheckpointE2E", "HASH_E2E_FITTED_OUTPUT_OWNED_PG", "fitted-output"},
	{"cmd/rollbackcheck", "TestFirstInstallFresh117ResourceBaseline", "HASH_FIRST_INSTALL_TEST_DB_URL", "first-install"},
}

const hashModule = "github.com/bright-interaction/hash/"

func optionalSkip(id testID, getenv func(string) string) (string, bool) {
	for _, entry := range optionalAcceptanceCatalog {
		if id.Package == hashModule+entry.Package && id.Test == entry.Test && getenv(entry.Flag) == "" {
			return entry.Profile, true
		}
	}
	return "", false
}
