// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
)

func TestAcknowledgementEmailModeReachesDurableOutbox(t *testing.T) {
	orgID := uuid.New()
	engine := &Engine{OrgName: "Partner Org"}
	for _, kind := range []string{dispatch.KindInvite, dispatch.KindReminder} {
		for _, locale := range []string{"en", "sv"} {
			t.Run(kind+"/"+locale, func(t *testing.T) {
				message, err := engine.renderEmail(
					kind,
					"recipient@example.test",
					"Recipient",
					"Policy",
					"sender@example.test",
					"https://hash.example.test/sign/token",
					"",
					locale,
					false,
				)
				if err != nil {
					t.Fatal(err)
				}
				message.OrgID = orgID // native callers stamp the retained document organization
				queue := &modeEmailQueue{}
				if err := enqueueLifecycleEmails(context.Background(), queue, []dispatch.Message{message}); err != nil {
					t.Fatal(err)
				}
				if len(queue.rows) != 1 {
					t.Fatalf("outbox rows = %d, want 1", len(queue.rows))
				}
				if queue.rows[0].OrgID != orgID {
					t.Fatal("outbox lost the native organization")
				}
				if queue.rows[0].ToEmail != message.To || queue.rows[0].Subject != message.Subject || queue.rows[0].HtmlBody != message.HTML || queue.rows[0].TextBody != message.Text {
					t.Fatal("outbox changed the selected recipient or localized message bytes")
				}
				assertAcknowledgementLifecycleCopy(t, queue.rows[0].Subject+"\n"+queue.rows[0].HtmlBody+"\n"+queue.rows[0].TextBody, locale)
			})
		}
	}
}

func TestAcknowledgementEmailModeReachesLocalMailer(t *testing.T) {
	mailer := modeChannelMailer(make(chan dispatch.Message, 2))
	orgID := uuid.New()
	engine := &Engine{OrgName: "Partner Org", Mailer: mailer}
	for _, kind := range []string{dispatch.KindInvite, dispatch.KindReminder} {
		engine.sendEmail(
			orgID,
			kind,
			"recipient@example.test",
			"Recipient",
			"Policy",
			"sender@example.test",
			"https://hash.example.test/sign/token",
			"",
			"en",
			false,
		)
		select {
		case message := <-mailer:
			if message.OrgID != orgID {
				t.Fatal("local mailer lost the native organization")
			}
			assertAcknowledgementLifecycleCopy(t, message.Subject+"\n"+message.HTML+"\n"+message.Text, "en")
		case <-time.After(2 * time.Second):
			t.Fatalf("%s was not delivered to the local mailer", kind)
		}
	}
}

func assertAcknowledgementLifecycleCopy(t *testing.T, rendered, locale string) {
	t.Helper()
	lower := strings.ToLower(rendered)
	wanted := []string{"acknowledg", "no signature will be requested"}
	switch locale {
	case "en":
	case "sv":
		wanted = []string{"bekräft", "ingen signatur kommer att begäras"}
	default:
		t.Fatalf("unsupported test locale %q", locale)
	}
	for _, want := range wanted {
		if !strings.Contains(lower, want) {
			t.Fatalf("%s acknowledgement email lost its ceremony mode (%q): %s", locale, want, rendered)
		}
	}
	for _, forbidden := range []string{"for signature", "review and sign", "awaiting your signature", "open and sign", "för signering", "granska och signera", "väntar på din signatur", "öppna och signera"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("acknowledgement email contains signing instruction %q: %s", forbidden, rendered)
		}
	}
}

type modeChannelMailer chan dispatch.Message

func (m modeChannelMailer) Send(ctx context.Context, message dispatch.Message) error {
	select {
	case m <- message:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type modeEmailQueue struct {
	rows []generated.EnqueueEmailDeliveryParams
}

func (q *modeEmailQueue) EnqueueEmailDelivery(_ context.Context, arg generated.EnqueueEmailDeliveryParams) (*generated.EmailDelivery, error) {
	q.rows = append(q.rows, arg)
	return &generated.EmailDelivery{ID: uuid.New(), ToEmail: arg.ToEmail}, nil
}
