// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package i18n

// Authored supplements for the Swedish email option. The absent upstream
// catalog is not regenerated and privacy/Article13 disclosures are untouched.
var swedishEmailSupplementV1 = map[string]string{
	"email.inviteAcknowledgement.subject":     "{sender} har skickat {document} för granskning och bekräftelse",
	"email.inviteAcknowledgement.eyebrow":     "Bekräftelse begärd",
	"email.inviteAcknowledgement.heading":     "{sender} har skickat {document} till dig",
	"email.inviteAcknowledgement.body":        "{sender} ({email}) ber dig att granska och bekräfta {document}. Ingen signatur kommer att begäras.",
	"email.inviteAcknowledgement.cta":         "Granska och bekräfta",
	"email.reminderAcknowledgement.subject":   "Påminnelse: {document} väntar på din bekräftelse",
	"email.reminderAcknowledgement.eyebrow":   "Påminnelse om bekräftelse",
	"email.reminderAcknowledgement.heading":   "{document} väntar fortfarande på din bekräftelse",
	"email.reminderAcknowledgement.body":      "Hej {recipient}, en påminnelse om att {sender} väntar på att du granskar och bekräftar dokumentet. Ingen signatur kommer att begäras.",
	"email.reminderAcknowledgement.cta":       "Granska och bekräfta",
	"email.completedSigner.body":              "Signeringen är klar. Använd länkarna nedan för att ladda ner och spara den färdiga signerade PDF-filen och dess separata granskningscertifikat före {expires_at}. Båda länkarna upphör att gälla då.",
	"email.completedSigner.auditCta":          "Ladda ner granskningscertifikat",
	"email.completedAcknowledgement.subject":  "Din färdiga kopia av {document}",
	"email.completedAcknowledgement.eyebrow":  "Bekräftat",
	"email.completedAcknowledgement.heading":  "Din färdiga kopia av {document}",
	"email.completedAcknowledgement.body":     "Alla obligatoriska bekräftelser är klara. Använd länkarna nedan för att ladda ner och spara den färdiga PDF-filen och dess separata granskningscertifikat före {expires_at}. Båda länkarna upphör att gälla då. Ingen signaturbild eller uppgift om att en part har signerat läggs till. Granskningscertifikatet dokumenterar bekräftelserna.",
	"email.completedAcknowledgement.cta":      "Ladda ner färdig PDF",
	"email.completedAcknowledgement.auditCta": "Ladda ner granskningscertifikat",
	"email.common.originalFilesCta":           "Ladda ner avtalets originalfiler",
}
