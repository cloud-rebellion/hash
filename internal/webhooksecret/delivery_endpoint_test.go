// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package webhooksecret

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestDeliveryEndpointBindsAuthenticatedActiveRow(t *testing.T) {
	keys, err := NewKeyringHex(keyHex(0x11), "")
	if err != nil {
		t.Fatal(err)
	}
	orgID, id := uuid.New(), uuid.New()
	secret := generatedSecret(0x22)
	ciphertext, err := keys.SealNew(orgID, id, secret)
	if err != nil {
		t.Fatal(err)
	}
	repo := newMemoryRepository(endpointRow{ID: id, OrgID: orgID, URL: "https://subscriber.example.invalid", Ciphertext: ciphertext, CiphertextPresent: true, Active: true})
	manager, err := newManagerWithRepository(keys, "", repo)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := manager.EndpointForDelivery(context.Background(), id)
	if err != nil || endpoint.ID != id || endpoint.OrgID != orgID || endpoint.URL != "https://subscriber.example.invalid" || endpoint.SigningSecret != secret || repo.replaces != 0 {
		t.Fatal("delivery identity and key did not come from authenticated active row")
	}
	raw, err := json.Marshal(endpoint)
	if err != nil || strings.Contains(string(raw), secret) || strings.Contains(string(raw), "SigningSecret") {
		t.Fatal("descriptor JSON exposed signing material")
	}
	// A copied ciphertext must not acquire a different org's routing authority.
	row := repo.rows[id]
	row.OrgID = uuid.New()
	repo.rows[id] = row
	if got, err := manager.EndpointForDelivery(context.Background(), id); err == nil || got != (DeliveryEndpoint{}) {
		t.Fatal("cross-org ciphertext acquired delivery authority")
	}
}

func TestDeliveryEndpointInactiveAndCancelledNeverExposeKey(t *testing.T) {
	keys, err := NewKeyringHex(keyHex(0x13), "")
	if err != nil {
		t.Fatal(err)
	}
	orgID, id := uuid.New(), uuid.New()
	secret := generatedSecret(0x24)
	ciphertext, err := keys.SealNew(orgID, id, secret)
	if err != nil {
		t.Fatal(err)
	}
	repo := newMemoryRepository(endpointRow{ID: id, OrgID: orgID, URL: "https://subscriber.example.invalid", Ciphertext: ciphertext, CiphertextPresent: true})
	manager, err := newManagerWithRepository(keys, "", repo)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := manager.EndpointForDelivery(context.Background(), id); !errors.Is(err, ErrEndpointInactive) || got != (DeliveryEndpoint{}) || repo.replaces != 0 {
		t.Fatal("inactive endpoint exposed key or migrated during delivery admission")
	}
	// Existing API remains compatible for non-delivery secret management callers.
	if url, got, err := manager.Endpoint(context.Background(), id); err != nil || url == "" || got != secret {
		t.Fatal("legacy Endpoint API was changed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := manager.EndpointForDelivery(ctx, id); !errors.Is(err, context.Canceled) || got != (DeliveryEndpoint{}) {
		t.Fatal("cancelled admission exposed key")
	}
}

type deliveryEndpointRaceRepository struct {
	*memoryRepository
	firstReplace func(endpointRow)
}

func (r *deliveryEndpointRaceRepository) replace(ctx context.Context, expected endpointRow, ciphertext []byte) (bool, error) {
	if r.firstReplace != nil {
		change := r.firstReplace
		r.firstReplace = nil
		change(expected)
		return false, nil
	}
	return r.memoryRepository.replace(ctx, expected, ciphertext)
}

func TestDeliveryEndpointCASRetryReturnsOnlyReauthenticatedRouting(t *testing.T) {
	for _, fault := range []string{"new authenticated tenant", "deactivated row", "invalid tenant ciphertext"} {
		t.Run(fault, func(t *testing.T) {
			keys, err := NewKeyringHex(keyHex(0x15), "")
			if err != nil {
				t.Fatal(err)
			}
			orgID, id, secret := uuid.New(), uuid.New(), generatedSecret(0x26)
			base := newMemoryRepository(endpointRow{ID: id, OrgID: orgID, URL: "https://old.example.invalid", Plaintext: secret, Active: true})
			newOrg, newSecret := uuid.New(), generatedSecret(0x27)
			repo := &deliveryEndpointRaceRepository{memoryRepository: base, firstReplace: func(old endpointRow) {
				row := old
				row.OrgID, row.URL, row.Plaintext = newOrg, "https://new.example.invalid", ""
				row.Ciphertext, err = keys.SealNew(newOrg, id, newSecret)
				if err != nil {
					t.Fatal(err)
				}
				row.CiphertextPresent = true
				if fault == "deactivated row" {
					row.Active = false
				}
				if fault == "invalid tenant ciphertext" {
					row.Ciphertext, err = keys.SealNew(orgID, id, secret)
					if err != nil {
						t.Fatal(err)
					}
				}
				base.rows[id] = row
			}}
			manager, err := newManagerWithRepository(keys, "", repo)
			if err != nil {
				t.Fatal(err)
			}
			got, err := manager.EndpointForDelivery(context.Background(), id)
			if fault == "new authenticated tenant" {
				if err != nil || got.OrgID != newOrg || got.URL != "https://new.example.invalid" || got.SigningSecret != newSecret {
					t.Fatal("CAS retry combined old account/key with new routing")
				}
			} else if err == nil || got != (DeliveryEndpoint{}) {
				t.Fatal("inactive or unauthentic raced row acquired delivery authority")
			}
		})
	}
}
