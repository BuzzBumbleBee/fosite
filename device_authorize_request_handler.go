/*
 * Copyright © 2015-2021 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2021 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package fosite

import (
	"context"
	"net/http"

	"github.com/ory/fosite/i18n"
	"github.com/ory/x/errorsx"
)

func (f *Fosite) NewDeviceAuthorizeRequest(ctx context.Context, r *http.Request) (DeviceAuthorizeRequester, error) {
	request := NewDeviceAuthorizeRequest()
	request.Lang = i18n.GetLangFromRequest(f.MessageCatalog, r)

	if err := r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebug(err.Error()))
	}
	request.Form = r.Form

	if request.GetRequestForm().Has("device_verifier") {
		client, err := f.Store.GetClient(ctx, request.GetRequestForm().Get("client_id"))
		if err != nil {
			return nil, errorsx.WithStack(ErrInvalidClient.WithHint("The requested OAuth 2.0 Client does not exist.").WithWrap(err).WithDebug(err.Error()))
		}
		request.Client = client

		if !client.GetGrantTypes().Has("urn:ietf:params:oauth:grant-type:device_code") {
			return nil, errorsx.WithStack(ErrInvalidGrant.WithHint("The requested OAuth 2.0 Client does not have the 'urn:ietf:params:oauth:grant-type:device_code' grant."))
		}
	}

	return request, nil
}
