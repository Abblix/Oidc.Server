// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Options;
using DeviceAuthorizationRequest = Abblix.Oidc.Server.Features.DeviceAuthorization.DeviceAuthorizationRequest;

namespace Abblix.Oidc.Server.Endpoints.DeviceAuthorization;

/// <summary>
/// Processes validated device authorization requests, generating codes and storing the request.
/// </summary>
/// <param name="storage">Storage for persisting device authorization requests.</param>
/// <param name="deviceCodeGenerator">Generator for high-entropy device codes.</param>
/// <param name="userCodeGenerator">Generator for user-friendly verification codes.</param>
/// <param name="options">Configuration options for device authorization.</param>
/// <param name="timeProvider">Dates the instant the device code carries.</param>
/// <param name="issuerProvider">The issuer a relative verification page is under.</param>
public class DeviceAuthorizationRequestProcessor(
    IDeviceAuthorizationStorage storage,
    IDeviceCodeGenerator deviceCodeGenerator,
    IUserCodeGenerator userCodeGenerator,
    IOptionsSnapshot<OidcOptions> options,
    TimeProvider timeProvider,
    IIssuerProvider issuerProvider) : IDeviceAuthorizationRequestProcessor
{
    /// <inheritdoc />
    public async Task<Result<DeviceAuthorizationResponse, OidcError>> ProcessAsync(
        ValidDeviceAuthorizationRequest request)
    {
        request.ClientInfo.CheckClientLicense();

        var deviceAuthOptions = options.Value.DeviceAuthorization.NotNull(nameof(OidcOptions.DeviceAuthorization));

        // The code carries its own expiry, so a poll after the record is evicted is still told expired_token
        var deviceCode = ExpiringIdentifier.Compose(
            deviceCodeGenerator.GenerateDeviceCode(),
            timeProvider.GetUtcNow() + deviceAuthOptions.CodeLifetime);
        var userCode = userCodeGenerator.GenerateUserCode();

        var deviceRequest = new DeviceAuthorizationRequest(
            request.ClientInfo.ClientId,
            request.Scope,
            request.Resources,
            userCode)
        {
            Status = DeviceAuthorizationStatus.Pending,

            // Nothing is written about when the device may first poll, and that absence IS the answer:
            // the token endpoint reads no instant for this code and lets the first poll through. RFC 8628
            // section 3.2 defines the interval as the minimum wait "between polling requests", so it
            // bounds the gap between two polls and has nothing to say before the first one.

            // RFC 9396 section 3: stash authorization_details on the persisted record so the
            // host's user-verification step can read it (via ValidUserCode) and thread it
            // onto the AuthorizedGrant's AuthorizationContext when approving.
            AuthorizationDetails = request.AuthorizationDetails,
        };

        await storage.StoreAsync(deviceCode, deviceRequest, deviceAuthOptions.CodeLifetime);

        var verificationUri = VerificationUri(deviceAuthOptions.VerificationUri);
        return new DeviceAuthorizationResponse
        {
            DeviceCode = deviceCode,
            UserCode = userCode,
            VerificationUri = verificationUri,

            // RFC 8628 section 3.2: verification_uri_complete lets capable devices render a direct link or QR
            // code, so the user skips typing the code
            VerificationUriComplete = new Uri(
                verificationUri.AddToQuery([(DeviceAuthorizationResponse.Parameters.UserCode, userCode)])),

            ExpiresIn = deviceAuthOptions.CodeLifetime,
            Interval = deviceAuthOptions.PollingInterval,
        };
    }

    /// <summary>
    /// The page the user enters the code on: <paramref name="configured"/> resolved against the issuer taken as a
    /// directory, which leaves an absolute one as it is (RFC 3986 section 5.2.2).
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// A relative page resolves outside the issuer, where under multi-tenancy it resolves no tenant, or under an
    /// issuer without TLS, where the user would authenticate in the clear.
    /// </exception>
    private Uri VerificationUri(Uri configured)
    {
        var issuer = new Uri(issuerProvider.GetIssuer().AppendTrailingSlash());
        var resolved = new Uri(issuer, configured);

        if (configured.IsAbsoluteUri)
            return resolved;

        if (!issuer.IsBaseOf(resolved))
        {
            throw new InvalidOperationException(
                $"The relative {nameof(DeviceAuthorizationOptions.VerificationUri)} '{configured}' resolves to " +
                $"{resolved}, outside the issuer {issuer}. Name a page under the issuer, such as 'device'.");
        }

        if (!string.Equals(resolved.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"The relative {nameof(DeviceAuthorizationOptions.VerificationUri)} resolves to {resolved}, which " +
                "does not use HTTPS: the user authenticates there, and RFC 6749 Section 3.1 requires TLS for that.");
        }

        return resolved;
    }
}
