package oauth2

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
)

// DeviceAuthorizationHandler is a response handler for the Device Authorisation Grant as
// defined in https://tools.ietf.org/html/rfc8628#section-3.1
type DeviceHandler struct {
	AccessTokenStrategy  AccessTokenStrategy
	RefreshTokenStrategy RefreshTokenStrategy
	DeviceCodeStrategy   DeviceCodeStrategy
	UserCodeStrategy     UserCodeStrategy
	CoreStorage          CoreStorage

	// AuthCodeLifespan defines the lifetime of an authorize code.
	DeviceAndUserCodeLifespan time.Duration

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan time.Duration

	// RefreshTokenLifespan defines the lifetime of a refresh token. Leave to 0 for unlimited lifetime.
	RefreshTokenLifespan time.Duration

	TokenRevocationStorage TokenRevocationStorage

	// PollingInterval defines the minimum amount of time in seconds that the client SHOULD wait between polling requests to the token endpoint.
	DeviceAuthTokenPollingInterval time.Duration

	DeviceVerificationURL string

	RefreshTokenScopes []string
}

func (d *DeviceHandler) HandleDeviceEndpointRequest(ctx context.Context, dar fosite.Requester, resp fosite.DeviceResponder) error {
	deviceCode, deviceCodeSignature, err := d.DeviceCodeStrategy.GenerateDeviceCode(ctx, dar)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	userCode, userCodeSignature, err := d.UserCodeStrategy.GenerateUserCode(ctx, dar)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// Save the real request_id
	requestId := dar.GetID()

	// Store the User Code session (this has no real data other that the uer and device code), can be converted into a 'full' session after user auth
	dar.GetSession().SetExpiresAt(fosite.AuthorizeCode, time.Now().UTC().Add(d.DeviceAndUserCodeLifespan))
	if err := d.CoreStorage.CreateDeviceCodeSession(ctx, deviceCodeSignature, dar.Sanitize(nil)); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// Fake the RequestId field to store the DeviceCodeSignature for easy handling
	dar.SetID(deviceCodeSignature)
	dar.GetSession().SetExpiresAt(fosite.UserCode, time.Now().UTC().Add(d.DeviceAndUserCodeLifespan).Round(time.Second))
	if err := d.CoreStorage.CreateUserCodeSession(ctx, userCodeSignature, dar.Sanitize(nil)); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	dar.SetID(requestId)

	// Populate the response fields
	resp.SetDeviceCode(deviceCode)
	resp.SetUserCode(userCode)
	resp.SetVerificationURI(d.DeviceVerificationURL)
	resp.SetVerificationURIComplete(d.DeviceVerificationURL + "?user_code=" + userCode)
	resp.SetExpiresIn(int64(time.Until(dar.GetSession().GetExpiresAt(fosite.UserCode)).Seconds()))
	resp.SetInterval(int(d.DeviceAuthTokenPollingInterval.Seconds()))
	return nil
}
