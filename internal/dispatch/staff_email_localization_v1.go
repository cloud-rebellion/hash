// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package dispatch

import (
	"fmt"
	"github.com/bright-interaction/hash/internal/i18n"
)

// Locale selects presentation copy only; capabilities and participant modes are
// unchanged. Owner producers supply the document's selected locale. Recipient
// producers keep the recipient's explicitly selected ceremony locale.
func nativeEmailTemplateSourcesV1(kind, locale string) (htmlSource, textSource string) {
	if kind == KindChangesRequested {
		_, h, p := changesRequestedSourcesV1(locale)
		return h, p
	}
	if i18n.Normalize(locale) == "sv" {
		switch kind {
		case KindCompletedSender:
			return completedSenderHTMLSV, completedSenderTextSV
		case KindDeclined:
			return declinedHTMLSV, declinedTextSV
		case KindNewComment:
			return newCommentHTMLSV, newCommentTextSV
		case KindVoided:
			return voidedHTMLSV, voidedTextSV
		case KindQuotaWarning80:
			return quotaWarning80HTMLSV, quotaWarning80TextSV
		}
	}
	return htmlFor(kind), textFor(kind)
}
func completedSenderSubjectSuffixV1(ctx TemplateContext) string {
	if i18n.Normalize(ctx.Locale) == "sv" {
		if ctx.Acknowledgement {
			return " – alla bekräftelser är klara"
		}
		return " – signeringen är klar"
	}
	if ctx.Acknowledgement {
		return " acknowledgements complete"
	}
	return " signing ceremony complete"
}
func commentSubjectPrefixV1(locale string) string {
	if i18n.Normalize(locale) == "sv" {
		return "Ny kommentar om "
	}
	return "New comment on "
}
func localizedStaffEmailSubjectV1(kind string, ctx TemplateContext) (string, bool) {
	if i18n.Normalize(ctx.Locale) != "sv" {
		return "", false
	}
	switch kind {
	case KindCompletedSender:
		return ctx.DocumentName + completedSenderSubjectSuffixV1(ctx), true
	case KindDeclined:
		return ctx.RecipientName + " har avböjt " + ctx.DocumentName, true
	case KindNewComment:
		return commentSubjectPrefixV1(ctx.Locale) + ctx.DocumentName, true
	case KindVoided:
		return ctx.DocumentName + " har annullerats", true
	case KindQuotaWarning80:
		return fmt.Sprintf("Information: %s-gränsen är nådd till %d%% i abonnemanget %s", ctx.QuotaKind, ctx.QuotaPct, ctx.PlanName), true
	}
	return "", false
}
func completedOriginalFilesLabelV1(locale string) string {
	if i18n.Normalize(locale) == "sv" {
		return i18n.T("sv", "email.common.originalFilesCta", nil)
	}
	return "Download original contract files"
}
func emailQuotaPresentationV1(ctx TemplateContext) TemplateContext {
	if i18n.Normalize(ctx.Locale) == "sv" {
		switch ctx.QuotaKind {
		case "documents":
			ctx.QuotaKind = "dokument"
		case "recipients":
			ctx.QuotaKind = "mottagare"
		}
	}
	return ctx
}

const completedSenderHTMLSV = `<!doctype html>
<html><body style="font-family: Inter, -apple-system, sans-serif; color: #111; padding: 24px; max-width: 560px;">
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">Klart</p>
{{if .Acknowledgement}}
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">{{.DocumentName}} har bekräftats av alla obligatoriska mottagare</h1>
<p>Alla obligatoriska mottagare har bekräftat dokumentet. Den färdiga PDF-filen innehåller ingen signaturbild eller uppgift om att en part har signerat. Ladda ner det separata granskningscertifikatet nedan som underlag för bekräftelserna.</p>
{{else}}
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">{{.DocumentName}} har signerats av alla obligatoriska signeringsroller</h1>
<p>Alla obligatoriska signeringsroller är klara. Den färdiga PDF-filen och dess separata granskningscertifikat kan laddas ner.</p>
{{end}}
{{if .DownloadURL}}<p style="margin: 24px 0;"><a href="{{.DownloadURL}}" style="background: #111; color: white; padding: 12px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">Ladda ner färdig PDF</a></p>{{end}}
{{if .AuditCertURL}}<p><a href="{{.AuditCertURL}}">Ladda ner granskningscertifikat</a></p>{{end}}
</body></html>`

const completedSenderTextSV = `{{if .Acknowledgement}}Alla obligatoriska bekräftelser för {{.DocumentName}} är klara. PDF-filen innehåller ingen signaturbild eller uppgift om att en part har signerat. Det separata granskningscertifikatet dokumenterar bekräftelserna.{{else}}Alla obligatoriska signeringsroller för {{.DocumentName}} är klara. Granskningscertifikatet tillhandahålls separat.{{end}}
Ladda ner färdig PDF: {{.DownloadURL}}
Granskningscertifikat: {{.AuditCertURL}}
`

const declinedHTMLSV = `<!doctype html>
<html><body style="font-family: Inter, -apple-system, sans-serif; color: #111; padding: 24px; max-width: 560px;">
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">Avböjt</p>
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">{{.RecipientName}} har avböjt {{.DocumentName}}</h1>
{{if .DeclineReason}}<p>Angivet skäl:</p><blockquote style="border-left: 3px solid #ccc; padding-left: 12px; color: #555;">{{.DeclineReason}}</blockquote>{{end}}
<p>Dokumentets status är nu avböjt. Inga fler signerare kommer att bjudas in.</p>
</body></html>`

const declinedTextSV = `{{.RecipientName}} har avböjt {{.DocumentName}}.
{{if .DeclineReason}}Skäl: {{.DeclineReason}}{{end}}
`

const newCommentHTMLSV = `<!doctype html>
<html><body style="font-family: Inter, -apple-system, sans-serif; color: #111; padding: 24px; max-width: 560px;">
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">Ny kommentar</p>
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">{{.RecipientName}} kommenterade {{.DocumentName}}</h1>
<blockquote style="border-left: 3px solid #0891B2; padding-left: 12px; color: #555; white-space: pre-wrap;">{{.DeclineReason}}</blockquote>
{{if .OpenURL}}<p style="margin-top: 20px;"><a href="{{.OpenURL}}" style="display: inline-block; background: #0891B2; color: #fff; text-decoration: none; padding: 10px 18px; border-radius: 6px; font-weight: 600;">Öppna dokumentet för att svara</a></p>{{else}}<p style="margin-top: 16px; color: #777;">Öppna signeringslänken i din inbjudan eller påminnelse, läs den aktuella integritetsinformationen och svara där.</p>{{end}}
</body></html>`

const newCommentTextSV = `{{.RecipientName}} kommenterade {{.DocumentName}}:
{{.DeclineReason}}
{{if .OpenURL}}Svara: {{.OpenURL}}{{else}}Öppna signeringslänken i din inbjudan eller påminnelse, läs den aktuella integritetsinformationen och svara där.{{end}}
`

const voidedHTMLSV = `<!doctype html>
<html><body style="font-family: Inter, -apple-system, sans-serif; color: #111; padding: 24px; max-width: 560px;">
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">Annullerat</p>
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">{{.DocumentName}} har annullerats</h1>
<p>{{.SenderName}} har annullerat dokumentet. Inga signaturer kommer att samlas in.</p>
</body></html>`

const voidedTextSV = `{{.DocumentName}} annullerades av {{.SenderName}}.
`

const quotaWarning80HTMLSV = `<!doctype html>
<html><body style="font-family: Inter, -apple-system, sans-serif; color: #111; padding: 24px; max-width: 560px;">
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">Användning</p>
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">{{.OrgName}} har nått {{.QuotaPct}}% av gränsen för {{.QuotaKind}} i abonnemanget {{.PlanName}}</h1>
<p>Du har använt <strong>{{.QuotaUsed}} av {{.QuotaLimit}}</strong> {{.QuotaKind}} denna {{if .InternalOperator}}kalendermånad{{else}}faktureringsperiod{{end}}. Räknaren nollställs <strong>{{.PeriodResetAt}}</strong>.</p>
<p>När gränsen nås pausas nya utskick till nästa period. {{if .InternalOperator}}Kontakta operatören för att se över kapaciteten innan gränsen nås.{{else}}Uppgradera nu för att undvika avbrott.{{end}}</p>
{{if .UpgradeURL}}<p style="margin: 24px 0;"><a href="{{.UpgradeURL}}" style="background: #111; color: white; padding: 12px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">Visa abonnemang</a></p>{{end}}
<p style="font-size: 11px; color: #999; margin-top: 32px;">Skickat via Hash. Du får högst ett sådant meddelande per {{if .InternalOperator}}kalendermånad{{else}}faktureringsperiod{{end}}.</p>
</body></html>`

const quotaWarning80TextSV = `{{.OrgName}} har nått {{.QuotaPct}}% av gränsen för {{.QuotaKind}} i abonnemanget {{.PlanName}}.

Använt: {{.QuotaUsed}} av {{.QuotaLimit}} {{.QuotaKind}} denna period.
Perioden nollställs: {{.PeriodResetAt}}

{{if .InternalOperator}}Kontakta operatören för att se över kapaciteten.
Visa internt abonnemang: {{.UpgradeURL}}{{else}}Visa eller uppgradera: {{.UpgradeURL}}{{end}}
`
