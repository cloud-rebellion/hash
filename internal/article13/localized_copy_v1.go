// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package article13

// CopyLocaleV1 selects from the server's recipient locale. Unsupported values
// retain the exact historical English wording; browser preferences are not input.
func CopyLocaleV1(recipientLocale string) string {
	if recipientLocale == "sv" {
		return "sv"
	}
	return "en"
}

// LocalizedMaterialV1 contains the actual notice strings placed in Snapshot.
// CopyLocale is view metadata only: V1 already hashes every displayed string.
// No locale field is added to the canonical snapshot or retained evidence.
type LocalizedMaterialV1 struct {
	CopyLocale           string
	PurposeSummary       string
	LegalBasisDisclosure string
	Copy                 Copy
}

// LocalizedNoticeV1 is the shared material builder for rendering and live
// acknowledgement checks. The original V1 English functions remain unchanged.
// Translation changes wording, not lawful basis, retention, rights or capability.
func LocalizedNoticeV1(documentName, lawfulBasis, recipientLocale string) (LocalizedMaterialV1, error) {
	legal, err := LegalBasisDisclosureV1(lawfulBasis)
	if err != nil {
		return LocalizedMaterialV1{}, err
	}
	material := LocalizedMaterialV1{
		CopyLocale: CopyLocaleV1(recipientLocale), PurposeSummary: PurposeSummaryV1(documentName),
		LegalBasisDisclosure: legal, Copy: RenderedCopyV1(documentName),
	}
	if material.CopyLocale != "sv" {
		return material, nil
	}
	material.PurposeSummary = "Administrera svarsprocessen för " + documentName +
		", registrera deltagarnas åtgärder, ta fram tillämpliga slutliga handlingar och bevara insamlade bevis enligt Hashs fasta policy om sju års bevarandetid för bevis. Den personuppgiftsansvarige måste säkerställa att perioden är laglig. Hash avgör inte dokumentets rättsverkan."
	material.LegalBasisDisclosure = "Personuppgiftsansvarig har bekräftat: GDPR artikel 6.1 b — behandling som är nödvändig för ett avtal eller för begärda åtgärder före ett avtal."
	material.Copy = Copy{
		Title:                  "Innan du svarar: så hanterar vi dina personuppgifter",
		Intro:                  "Du ska svara på " + documentName + ". Enligt artikel 13 i GDPR ska vi informera dig om vem som behandlar dina personuppgifter, varför och hur du utövar dina rättigheter.",
		ControllerLabel:        "Personuppgiftsansvarig",
		ControllerContactLabel: "Kontakt till personuppgiftsansvarig",
		ProcessorLabel:         "Personuppgiftsbiträde",
		PurposeLabel:           "Ändamål",
		LegalBasisLabel:        "Rättslig grund",
		RetentionLabel:         "Bevarandetid",
		RetentionValue:         "Hash tillämpar en fast bevarandetid på 7 år för självständigt ägda källversioner eller renderade PDF-versioner när ett dokument skickas, färdigställda slutliga PDF-filer och granskningscertifikat samt signaturmaterial som har samlats in innan en signeringsprocess senare avslutas utan att slutföras. Den personuppgiftsansvarige måste säkerställa att perioden stämmer med tillämpligt avtal och lag.",
		AuthorityLabel:         "Tillsynsmyndighet",
		RightsSummary:          "Dina rättigheter enligt artiklarna 15–22 i GDPR",
		RightsBody:             "Tillgång, rättelse, radering, begränsning, dataportabilitet och invändning. Använd formuläret nedan för att skicka en begäran direkt från den här sidan.",
		SubmitRequestLabel:     "Skicka en begäran om dina rättigheter",
		KindLabel:              "Typ av begäran",
		DSRAccessLabel:         "Tillgång (art. 15)",
		DSRRectificationLabel:  "Rättelse (art. 16)",
		DSRErasureLabel:        "Radering (art. 17)",
		DSRRestrictionLabel:    "Begränsning (art. 18)",
		DSRPortabilityLabel:    "Dataportabilitet (art. 20)",
		DSRObjectionLabel:      "Invändning (art. 21)",
		NoteLabel:              "Meddelande (valfritt)",
		NotePlaceholder:        "Information som hjälper oss att avgränsa begäran",
		SendRequestLabel:       "Skicka begäran",
		RequestReceived:        "Begäran har tagits emot. Den personuppgiftsansvarige svarar inom den tillämpliga tidsfristen i GDPR. Identitetskontroller eller en laglig förlängning kan påverka tiden.",
		ReadPolicyLabel:        "Läs hela integritetspolicyn",
		AcknowledgementLabel:   "Jag förstår, fortsätt",
		FinePrint:              "Du måste bekräfta att du har tagit del av detta meddelande för att svara på dokumentet. Bekräftelsen ändrar inte Hashs fasta bevarandetid för bevis. Radering är fortsatt begränsad av oföränderlig lagring och den personuppgiftsansvariges tillämpliga skyldigheter.",
	}
	return material, nil
}
