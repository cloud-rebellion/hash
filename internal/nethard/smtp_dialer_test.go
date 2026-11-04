// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package nethard

import "testing"

func TestWorkspaceSMTPDialerChecksExactResolvedIP730(t *testing.T) {
	blocked := []string{"127.0.0.1:587", "10.2.3.4:587", "169.254.169.254:465", "100.118.61.16:587", "[::1]:465", "[::ffff:127.0.0.1]:587", "198.18.0.1:465"}
	d := Dialer(func() bool { return false })
	for _, address := range blocked {
		if d.Control("tcp", address, nil) == nil {
			t.Fatal("private resolved SMTP destination accepted", address)
		}
	}
	if e := d.Control("tcp", "8.8.8.8:587", nil); e != nil {
		t.Fatal("public exact dial address refused", e)
	}
	if Dialer(func() bool { return true }).Control("tcp", "127.0.0.1:587", nil) != nil {
		t.Fatal("explicit operator local-development allowance lost")
	}
}
