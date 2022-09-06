package oauth2

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/ory/x/errorsx"
)

const deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

func (c *AuthorizeDeviceGrantTypeHandler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(errorsx.WithStack(fosite.ErrUnknownRequest))
	}

	if !requester.GetClient().GetGrantTypes().Has(deviceCodeGrantType) {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"" + deviceCodeGrantType + "\"."))
	}

	code := requester.GetRequestForm().Get("device_code")
	if code == "" {
		return errorsx.WithStack(errorsx.WithStack(fosite.ErrUnknownRequest.WithHint("device_code missing form body")))
	}
	codeSignature := c.DeviceCodeStrategy.DeviceCodeSignature(ctx, code)

	// Get the device code session to validate based on HMAC of the device code supplied
	deviceRequest, err := c.CoreStorage.GetDeviceCodeSession(ctx, codeSignature, requester.GetSession())
	if err != nil {
		return errorsx.WithStack(fosite.ErrAuthorizationPending)
	}

	requester.SetRequestedScopes(deviceRequest.GetRequestedScopes())
	requester.SetRequestedAudience(deviceRequest.GetRequestedAudience())
	if requester.GetClient().GetID() != deviceRequest.GetClient().GetID() {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client ID from this request does not match the one from the authorize request."))
	}

	atLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	requester.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))

	rtLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.RefreshToken, c.Config.GetRefreshTokenLifespan(ctx))
	if rtLifespan > -1 {
		requester.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(rtLifespan).Round(time.Second))
	}

	return nil
}

func (c *AuthorizeDeviceGrantTypeHandler) canIssueRefreshToken(ctx context.Context, config *AuthorizeDeviceGrantTypeHandler, request fosite.Requester) bool {
	scope := config.Config.GetRefreshTokenScopes(ctx)
	// Require one of the refresh token scopes, if set.
	if len(scope) > 0 && !request.GetGrantedScopes().HasOneOf(scope...) {
		return false
	}
	// Do not issue a refresh token to clients that cannot use the refresh token grant type.
	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
		return false
	}
	return true
}

func (c *AuthorizeDeviceGrantTypeHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	code := requester.GetRequestForm().Get("device_code")
	if code == "" {
		return errorsx.WithStack(errorsx.WithStack(fosite.ErrUnknownRequest.WithHint("device_code missing form body")))
	}
	signature := c.DeviceCodeStrategy.DeviceCodeSignature(ctx, code)

	if err := c.DeviceCodeStrategy.ValidateDeviceCode(ctx, requester, code); err != nil {
		// This needs to happen after store retrieval for the session to be hydrated properly
		return err
	}

	deviceRequest, err := c.CoreStorage.GetDeviceCodeSession(ctx, signature, requester.GetSession())
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if err := c.DeviceCodeStrategy.ValidateDeviceCode(ctx, requester, code); err != nil {
		// This needs to happen after store retrieval for the session to be hydrated properly
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithWrap(err).WithDebug(err.Error()))
	}

	for _, scope := range deviceRequest.GetGrantedScopes() {
		requester.GrantScope(scope)
	}

	for _, audience := range deviceRequest.GetGrantedAudience() {
		requester.GrantAudience(audience)
	}

	access, accessSignature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	var refresh, refreshSignature string
	if c.canIssueRefreshToken(ctx, c, deviceRequest) {
		refresh, refreshSignature, err = c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
		if err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	ctx, err = storage.MaybeBeginTx(ctx, c.CoreStorage)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	defer func() {
		if err != nil {
			if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.CoreStorage); rollBackTxnErr != nil {
				err = errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebugf("error: %s; rollback error: %s", err, rollBackTxnErr))
			}
		}
	}()

	if err = c.CoreStorage.InvalidateDeviceCodeSession(ctx, signature); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if err = c.CoreStorage.CreateAccessTokenSession(ctx, accessSignature, requester.Sanitize([]string{})); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if refreshSignature != "" {
		if err = c.CoreStorage.CreateRefreshTokenSession(ctx, refreshSignature, requester.Sanitize([]string{})); err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	responder.SetAccessToken(access)
	responder.SetTokenType("bearer")
	atLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, atLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	if refresh != "" {
		responder.SetExtra("refresh_token", refresh)
	}

	if err = storage.MaybeCommitTx(ctx, c.CoreStorage); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return nil
}

func (c *AuthorizeDeviceGrantTypeHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return true
}

func (c *AuthorizeDeviceGrantTypeHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "urn:ietf:params:oauth:grant-type:device_code"
	return requester.GetGrantTypes().ExactOne(deviceCodeGrantType)
}
