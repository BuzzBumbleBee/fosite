/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
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
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package fosite

import "net/url"

// DeviceAuthorizeRequest is an implementation of DeviceAuthorizeRequester
type DeviceAuthorizeRequest struct {
	deviceCodeSignature string
	deviceDoneUrl       *url.URL
	Request
}

func (d *DeviceAuthorizeRequest) GetDeviceCodeSignature() string {
	return d.deviceCodeSignature
}

func (d *DeviceAuthorizeRequest) SetDeviceCodeSignature(signature string) {
	d.deviceCodeSignature = signature
}

func (d *DeviceAuthorizeRequest) GetDeviceDoneUrl() *url.URL {
	return d.deviceDoneUrl
}

func (d *DeviceAuthorizeRequest) SetDeviceDoneUrl(url *url.URL) {
	d.deviceDoneUrl = url
}

func NewDeviceAuthorizeRequest() *DeviceAuthorizeRequest {
	return &DeviceAuthorizeRequest{
		Request: *NewRequest(),
	}
}
