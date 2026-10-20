// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package dispatch

import (
	"errors"
	"math"
)

var errCommentNotificationSizeV1 = errors.New("comment notification size overflows")

// Bounds ONE actual unchanged KindNewComment output by concrete components.
// This is logical work/output accounting, not allocator/RSS or SQL authority.
// Original Render still decides URL policy. Both templates use html/template.
func CommentNotificationComponentsV1(ctx TemplateContext) (subjectBytes, htmlBytes, textBytes int64, err error) {
	subjectBytes, err = addCommentNotificationBytesV1(int64(len("New comment on ")), int64(len(ctx.DocumentName)), 1)
	if err != nil {
		return 0, 0, 0, err
	}
	htmlBytes, textBytes = int64(len(newCommentHTML)), int64(len(newCommentText))
	for _, v := range [...]string{ctx.RecipientName, ctx.DocumentName, ctx.DeclineReason} {
		htmlBytes, err = addCommentNotificationBytesV1(htmlBytes, int64(len(v)), 6)
		if err != nil {
			return 0, 0, 0, err
		}
		textBytes, err = addCommentNotificationBytesV1(textBytes, int64(len(v)), 6)
		if err != nil {
			return 0, 0, 0, err
		}
	}
	htmlBytes, err = addCommentNotificationBytesV1(htmlBytes, int64(len(ctx.OpenURL)), 18)
	if err != nil {
		return 0, 0, 0, err
	}
	htmlBytes, err = addCommentNotificationBytesV1(htmlBytes, int64(len("#ZgotmplZ")), 1)
	if err != nil {
		return 0, 0, 0, err
	}
	textBytes, err = addCommentNotificationBytesV1(textBytes, int64(len(ctx.OpenURL)), 6)
	if err != nil {
		return 0, 0, 0, err
	}
	return subjectBytes, htmlBytes, textBytes, nil
}
func CommentNotificationTemplateSourceBytesV1() int64 {
	return int64(len(newCommentHTML) + len(newCommentText))
}
func addCommentNotificationBytesV1(total, size, factor int64) (int64, error) {
	if total < 0 || size < 0 || factor <= 0 || size > (math.MaxInt64-total)/factor {
		return 0, errCommentNotificationSizeV1
	}
	return total + size*factor, nil
}
