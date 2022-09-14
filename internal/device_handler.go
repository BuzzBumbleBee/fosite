// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ory/fosite (interfaces: DeviceEndpointHandler)

// Package internal is a generated GoMock package.
package internal

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	fosite "github.com/ory/fosite"
)

// MockDeviceEndpointHandler is a mock of DeviceEndpointHandler interface.
type MockDeviceEndpointHandler struct {
	ctrl     *gomock.Controller
	recorder *MockDeviceEndpointHandlerMockRecorder
}

// MockDeviceEndpointHandlerMockRecorder is the mock recorder for MockDeviceEndpointHandler.
type MockDeviceEndpointHandlerMockRecorder struct {
	mock *MockDeviceEndpointHandler
}

// NewMockDeviceEndpointHandler creates a new mock instance.
func NewMockDeviceEndpointHandler(ctrl *gomock.Controller) *MockDeviceEndpointHandler {
	mock := &MockDeviceEndpointHandler{ctrl: ctrl}
	mock.recorder = &MockDeviceEndpointHandlerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDeviceEndpointHandler) EXPECT() *MockDeviceEndpointHandlerMockRecorder {
	return m.recorder
}

// HandleDeviceEndpointRequest mocks base method.
func (m *MockDeviceEndpointHandler) HandleDeviceEndpointRequest(arg0 context.Context, arg1 fosite.Requester, arg2 fosite.DeviceResponder) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HandleDeviceEndpointRequest", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// HandleDeviceEndpointRequest indicates an expected call of HandleDeviceEndpointRequest.
func (mr *MockDeviceEndpointHandlerMockRecorder) HandleDeviceEndpointRequest(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandleDeviceEndpointRequest", reflect.TypeOf((*MockDeviceEndpointHandler)(nil).HandleDeviceEndpointRequest), arg0, arg1, arg2)
}