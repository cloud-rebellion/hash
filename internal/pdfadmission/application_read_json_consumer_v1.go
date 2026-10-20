// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// Serialized JSON contains no aliases into native rows. Its real body loan can
// outlive a closed producer without keeping the whole Work's source borrowers
// alive. The original admission still requires actual physical SQL retirement
// and this consumer's last use before its coordinator grant can be released.
type applicationReadJSONConsumerV1 struct {
	once    sync.Once
	release func()
}

func (c *applicationReadJSONConsumerV1) CloseConsumerV1() {
	if c != nil {
		c.once.Do(func() {
			if c.release != nil {
				c.release()
				c.release = nil
			}
		})
	}
}

// The sign-layer field/comment results have this same fixed header layout.
// This private cost shape carries no identity, SQL authority or mutable source.
type applicationReadJSONResultShapeV1 struct {
	JSON    []byte
	self    *applicationReadJSONResultShapeV1
	once    sync.Once
	release func()
}

func readJSONRetainedControlBytesV1() (int64, error) {
	// The retained admission proof still references closed native objects,
	// including opaque pgx connection/configuration buffers. Preserve the ENTIRE
	// existing32MiB native working class in Parent via the unchanged8*raw cost;
	// sizeof below is additional control storage, never a deep-heap/RSS claim.
	// Only the finished producer's DB staging class ends at physical retirement.
	// JSON itself retains the unchanged generic fixed+16*actual-wire DB cost.
	total := htmlAuthoringOtherWorkV1 / 8
	for _, size := range []int64{
		int64(unsafe.Sizeof(ApplicationHTMLAuthoringReaderV1{})),
		int64(unsafe.Sizeof(applicationHTMLAuthoringBodyHeaderV1{})),
		int64(unsafe.Sizeof(applicationHTMLAuthoringBodyGrantV1{})),
		int64(unsafe.Sizeof(ApplicationSessionV1{})),
		int64(unsafe.Sizeof(applicationOwnedSessionV1{})),
		int64(unsafe.Sizeof(applicationSessionFenceV1{})),
		int64(unsafe.Sizeof(ApplicationAdmissionV1{})),
		int64(unsafe.Sizeof(applicationLoanV1{})),
		int64(unsafe.Sizeof(ApplicationBudgetV1{})),
		int64(unsafe.Sizeof(applicationHTMLAdmissionRegistrationV1{})),
		int64(unsafe.Sizeof(applicationIssuerV1{})),
		int64(unsafe.Sizeof(applicationOwnedDBTXV1{})),
		int64(unsafe.Sizeof(generated.Queries{})),
		int64(unsafe.Sizeof(ApplicationHTMLSendWorkV1{})),
		int64(unsafe.Sizeof(ApplicationHTMLSendOperationV1{})),
		int64(unsafe.Sizeof(ApplicationHTMLSendSQLStageV1{})),
		int64(unsafe.Sizeof(applicationReadJSONConsumerV1{})),
		4 * int64(unsafe.Sizeof(applicationReadJSONResultShapeV1{})),
		8 * int64(unsafe.Sizeof(struct {
			once    sync.Once
			release func()
			owner   unsafe.Pointer
		}{})),
	} {
		if !htmlStoredRetentionAllocV1(&total, size) {
			return 0, ErrHTMLAuthoringReadV1
		}
	}
	return htmlStoredRetentionFinishV1(total)
}
