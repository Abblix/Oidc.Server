// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using CoreResponse = Abblix.Oidc.Server.Model.DeviceAuthorizationResponse;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Handles the formatting of responses for device authorization requests (RFC 8628): the device-code response on
/// success, as the endpoint's processor completed it, or the OAuth error on failure.
/// </summary>
/// <param name="tenantAccessor">Names the tenant the request is served at.</param>
public class DeviceAuthorizationResponseFormatter(ITenantAccessor tenantAccessor) : IDeviceAuthorizationResponseFormatter
{
    /// <summary>
    /// Formats a device authorization response into an HTTP response.
    /// </summary>
    public Task<ActionResult> FormatResponseAsync(
        DeviceAuthorizationRequest request,
        Result<CoreResponse, OidcError> response)
    {
        return Task.FromResult(response.Match<ActionResult>(
            onSuccess: success => new OkObjectResult(success),
            // RFC 8628 section 3.2: an error is answered "in the same way as the token endpoint specified in
            // Section 5.2 of [RFC6749]", so through the token endpoint's own policy (invalid_client -> 401).
            onFailure: error => error.Format(
                StatusCodes.Status400BadRequest,
                tenantAccessor.CurrentTenant().Issuer.OriginalString)));
    }
}
