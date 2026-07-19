// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using CoreResponse = Abblix.Oidc.Server.Model.DeviceAuthorizationResponse;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats device authorization results (RFC 8628) as <see cref="IResult"/>: a JSON device-code response on success, or
/// the JSON OAuth error on failure. The verification URIs, code lifetime and polling interval are taken from the
/// configured device authorization options.
/// </summary>
/// <param name="options">Configuration options containing device authorization settings.</param>
public class DeviceAuthorizationResultFormatter(
    IOptions<OidcOptions> options) : IDeviceAuthorizationResultFormatter
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
                    // RFC 8628 §3.2: verification_uri_complete lets capable devices render a direct link / QR code so
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
