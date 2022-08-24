package oauth2

import (
	"context"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/ory/x/errorsx"
)

const deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

func (d *AuthorizeDeviceGrantTypeHandler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {

	if !d.CanHandleTokenEndpointRequest(requester) {
		return errorsx.WithStack(errorsx.WithStack(fosite.ErrUnknownRequest))
	}

	code := requester.GetRequestForm().Get("device_code")
	if code == "" {
		return errorsx.WithStack(errorsx.WithStack(fosite.ErrUnknownRequest.WithHint("device_code missing form body")))
	}

	session, err := d.CoreStorage.GetDeviceCodeSession(ctx, code, requester.GetSession())

	if err != nil {
		return errorsx.WithStack(fosite.ErrDeviceTokenPending)
	}

	requester.SetRequestedScopes(session.GetRequestedScopes())
	requester.SetRequestedAudience(session.GetRequestedAudience())

	if requester.GetClient().GetID() != session.GetClient().GetID() {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client ID from this request does not match the one from the authorize request."))
	}

	requester.SetSession(session.GetSession())
	requester.SetID(session.GetID())

	atLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.AccessToken, d.AccessTokenLifespan)
	requester.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))

	rtLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.RefreshToken, d.RefreshTokenLifespan)
	if rtLifespan > -1 {
		requester.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(rtLifespan).Round(time.Second))
	}

	return nil
}

func (d *AuthorizeDeviceGrantTypeHandler) CanSkipClientAuth(requester fosite.AccessRequester) bool {
	return true
}

func (d *AuthorizeDeviceGrantTypeHandler) CanHandleTokenEndpointRequest(requester fosite.AccessRequester) bool {
	fmt.Println("DeviceAuthorizationHandler : CanHandleTokenEndpointRequest")
	return requester.GetGrantTypes().ExactOne(deviceCodeGrantType)
}

func (d *AuthorizeDeviceGrantTypeHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {

	if !d.CanHandleTokenEndpointRequest(requester) {
		return errorsx.WithStack(errorsx.WithStack(fosite.ErrUnknownRequest))
	}

	code := requester.GetRequestForm().Get("device_code")
	if code == "" {
		return errorsx.WithStack(errorsx.WithStack(fosite.ErrUnknownRequest.WithHint("device_code missing form body")))
	}

	session, err := d.CoreStorage.GetDeviceCodeSession(ctx, code, requester.GetSession())

	if err != nil {
		return errorsx.WithStack(errorsx.WithStack(fosite.ErrConsentRequired))
	}

	for _, scope := range session.GetGrantedScopes() {
		requester.GrantScope(scope)
	}

	for _, audience := range session.GetGrantedAudience() {
		requester.GrantAudience(audience)
	}

	access, accessSignature, err := d.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	refresh, refreshSignature, err := d.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	ctx, err = storage.MaybeBeginTx(ctx, d.CoreStorage)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	defer func() {
		if err != nil {
			if rollBackTxnErr := storage.MaybeRollbackTx(ctx, d.CoreStorage); rollBackTxnErr != nil {
				err = errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebugf("error: %s; rollback error: %s", err, rollBackTxnErr))
			}
		}
	}()

	if err = d.CoreStorage.DeleteDeviceCodeSession(ctx, code); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if err = d.CoreStorage.CreateAccessTokenSession(ctx, accessSignature, requester.Sanitize([]string{})); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if refreshSignature != "" {
		if err = d.CoreStorage.CreateRefreshTokenSession(ctx, refreshSignature, requester.Sanitize([]string{})); err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	responder.SetAccessToken(access)
	responder.SetTokenType("bearer")
	atLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.AccessToken, d.AccessTokenLifespan)
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, atLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	if refresh != "" {
		responder.SetExtra("refresh_token", refresh)
	}

	if err = storage.MaybeCommitTx(ctx, d.CoreStorage); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return nil
}

func (c *AuthorizeDeviceGrantTypeHandler) canIssueRefreshToken(request fosite.Requester) bool {
	// Require one of the refresh token scopes, if set.
	if len(c.RefreshTokenScopes) > 0 && !request.GetGrantedScopes().HasOneOf(c.RefreshTokenScopes...) {
		return false
	}
	// Do not issue a refresh token to clients that cannot use the refresh token grant type.
	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
		return false
	}
	return true
}