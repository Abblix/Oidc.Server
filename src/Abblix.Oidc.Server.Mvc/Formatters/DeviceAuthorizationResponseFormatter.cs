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
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using CoreResponse = Abblix.Oidc.Server.Model.DeviceAuthorizationResponse;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Handles the formatting of responses for device authorization requests (RFC 8628).
/// This class ensures that the appropriate HTTP responses are generated, including
/// verification URIs and formatted user codes.
/// </summary>
/// <param name="options">Configuration options containing device authorization settings.</param>
public class DeviceAuthorizationResponseFormatter(
    IOptions<OidcOptions> options) : IDeviceAuthorizationResponseFormatter
{
    /// <summary>
    /// Formats a device authorization response into an HTTP response.
    /// </summary>
    public Task<ActionResult> FormatResponseAsync(
        DeviceAuthorizationRequest request,
        Result<CoreResponse, OidcError> response)
    {
        return Task.FromResult(response.Match<ActionResult>(
            onSuccess: success =>
            {
                var deviceAuthOptions = options.Value.DeviceAuthorization
                    .NotNull(nameof(OidcOptions.DeviceAuthorization));

                var deviceResponse = new CoreResponse
                {
                    DeviceCode = success.DeviceCode,
                    UserCode = success.UserCode,
                    VerificationUri = deviceAuthOptions.VerificationUri,
                    // RFC 8628 §3.2: verification_uri_complete lets capable devices render a
                    // direct link / QR code so the user skips typing the code. The field was
                    // declared on the wire model but never populated.
                    VerificationUriComplete = new Uri(
                        deviceAuthOptions.VerificationUri.AddToQuery(
                            [(CoreResponse.Parameters.UserCode, success.UserCode)])),
                    ExpiresIn = deviceAuthOptions.CodeLifetime,
                    Interval = deviceAuthOptions.PollingInterval,
                };

                return new OkObjectResult(deviceResponse);
            },
            onFailure: error => new BadRequestObjectResult(
                new ErrorResponse(error.Error, error.ErrorDescription))));
    }
}
