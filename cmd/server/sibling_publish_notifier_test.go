package main

import (
	"context"
	"errors"
	"testing"

	"github.com/nanb/nanb-server/internal/proto"
)

type fakeDeviceLister struct {
	devices []proto.Device
	err     error
}

func (f fakeDeviceLister) ListActiveDevicesByAccountID(context.Context, string) ([]proto.Device, error) {
	return f.devices, f.err
}

type recordingChangedSender struct{ sent [][]string }

func (r *recordingChangedSender) NotifyDevicesChanged(ids []string) {
	r.sent = append(r.sent, ids)
}

func TestSiblingPublishNotifier_TellsTheOtherDevices(t *testing.T) {
	sender := &recordingChangedSender{}
	n := siblingPublishNotifier{
		devices: fakeDeviceLister{devices: []proto.Device{
			{DeviceID: "phone"}, {DeviceID: "web"}, {DeviceID: "tablet"},
		}},
		changed: sender,
	}
	n.notify("acct", "web")
	if len(sender.sent) != 1 || len(sender.sent[0]) != 2 ||
		sender.sent[0][0] != "phone" || sender.sent[0][1] != "tablet" {
		t.Fatalf("sent = %v, want [[phone tablet]]", sender.sent)
	}
}

func TestSiblingPublishNotifier_SingleDeviceSendsNothing(t *testing.T) {
	sender := &recordingChangedSender{}
	n := siblingPublishNotifier{
		devices: fakeDeviceLister{devices: []proto.Device{{DeviceID: "phone"}}},
		changed: sender,
	}
	n.notify("acct", "phone")
	if len(sender.sent) != 0 {
		t.Fatalf("sent = %v, want nothing", sender.sent)
	}
}

func TestSiblingPublishNotifier_LookupFailureSendsNothing(t *testing.T) {
	sender := &recordingChangedSender{}
	n := siblingPublishNotifier{
		devices: fakeDeviceLister{err: errors.New("db down")},
		changed: sender,
	}
	n.notify("acct", "phone")
	if len(sender.sent) != 0 {
		t.Fatalf("sent = %v, want nothing", sender.sent)
	}
}
