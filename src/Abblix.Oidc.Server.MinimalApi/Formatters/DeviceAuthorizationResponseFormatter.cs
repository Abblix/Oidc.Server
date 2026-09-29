// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using CoreResponse = Abblix.Oidc.Server.Model.DeviceAuthorizationResponse;

using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats device authorization results (RFC 8628) as <see cref="IResult"/>: the JSON device-code response on success,
/// as the endpoint's processor completed it, or the JSON OAuth error on failure.
/// </summary>
public class DeviceAuthorizationResponseFormatter : IDeviceAuthorizationResponseFormatter
{
    /// <inheritdoc />
    public Task<IResult> FormatResponseAsync(
        DeviceAuthorizationRequest request,
        Result<CoreResponse, OidcError> response)
    {
        return Task.FromResult(response.Match<IResult>(
            onSuccess: success => Results.Json(success),
            onFailure: error => Results.Json(
                new ErrorResponse(error.Error, error.ErrorDescription),
                statusCode: StatusCodes.Status400BadRequest)));
    }
}
