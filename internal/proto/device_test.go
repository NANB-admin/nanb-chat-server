package proto

import (
	"testing"
	"time"
)

func TestDevice_ActiveAt_NoExpiryIsAlwaysActive(t *testing.T) {
	d := Device{}
	if !d.ActiveAt(time.Unix(9_999_999_999, 0)) {
		t.Fatal("a device without expires_at must never expire")
	}
}

func TestDevice_ActiveAt_BeforeExpiryIsActive(t *testing.T) {
	exp := time.Unix(1000, 0)
	d := Device{ExpiresAt: &exp}
	if !d.ActiveAt(time.Unix(999, 0)) {
		t.Fatal("device must be active before expires_at")
	}
}

func TestDevice_ActiveAt_AtExpiryIsInactive(t *testing.T) {
	exp := time.Unix(1000, 0)
	d := Device{ExpiresAt: &exp}
	if d.ActiveAt(exp) {
		t.Fatal("expires_at <= now means expired")
	}
}

func TestDevice_ActiveAt_AfterExpiryIsInactive(t *testing.T) {
	exp := time.Unix(1000, 0)
	d := Device{ExpiresAt: &exp}
	if d.ActiveAt(time.Unix(1001, 0)) {
		t.Fatal("device must be inactive after expires_at")
	}
}

func TestValidDeviceKind(t *testing.T) {
	for _, k := range []string{"phone", "web"} {
		if !ValidDeviceKind(k) {
			t.Fatalf("%q should be valid", k)
		}
	}
	for _, k := range []string{"", "tablet", "WEB"} {
		if ValidDeviceKind(k) {
			t.Fatalf("%q should be invalid", k)
		}
	}
}
