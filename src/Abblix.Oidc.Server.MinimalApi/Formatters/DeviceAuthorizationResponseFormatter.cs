// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using CoreResponse = Abblix.Oidc.Server.Model.DeviceAuthorizationResponse;

using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats device authorization results (RFC 8628) as <see cref="IResult"/>: a JSON device-code response on success, or
/// the JSON OAuth error on failure. The verification URIs, code lifetime and polling interval are taken from the
/// configured device authorization options.
/// </summary>
/// <param name="options">Configuration options containing device authorization settings.</param>
public class DeviceAuthorizationResponseFormatter(
    IOptions<OidcOptions> options) : IDeviceAuthorizationResponseFormatter
{
    /// <inheritdoc />
    public Task<IResult> FormatResponseAsync(
        DeviceAuthorizationRequest request,
        Result<CoreResponse, OidcError> response)
    {
        return Task.FromResult(response.Match<IResult>(
            onSuccess: success =>
            {
                var deviceAuthOptions = options.Value.DeviceAuthorization
                    .NotNull(nameof(OidcOptions.DeviceAuthorization));

                var deviceResponse = new CoreResponse
                {
                    DeviceCode = success.DeviceCode,
                    UserCode = success.UserCode,
                    VerificationUri = deviceAuthOptions.VerificationUri,
                    // RFC 8628 section 3.2: verification_uri_complete lets capable devices render a direct link / QR code so
                    // the user skips typing the code.
                    VerificationUriComplete = new Uri(
                        deviceAuthOptions.VerificationUri.AddToQuery(
                            [(CoreResponse.Parameters.UserCode, success.UserCode)])),
                    ExpiresIn = deviceAuthOptions.CodeLifetime,
                    Interval = deviceAuthOptions.PollingInterval,
                };

                return Results.Json(deviceResponse);
            },
            onFailure: error => Results.Json(
                new ErrorResponse(error.Error, error.ErrorDescription),
                statusCode: StatusCodes.Status400BadRequest)));
    }
}
