// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Utils;
using Microsoft.Extensions.Options;

using System.Buffers.Text;

namespace Abblix.Oidc.Server.Features.RandomGenerators;

/// <summary>
/// Default <see cref="IAuthorizationRequestUriGenerator"/> implementation. Appends a URL-safe Base64 encoded
/// block of cryptographically secure random bytes (length governed by <see cref="OidcOptions.RequestUriLength"/>)
/// to <see cref="RequestUrn.Prefix"/>, producing the <c>urn:</c>-style <c>request_uri</c> values used by
/// Pushed Authorization Requests (RFC 9126).
/// </summary>
public class AuthorizationRequestUriGenerator(IOptions<OidcOptions> options) : IAuthorizationRequestUriGenerator
{
    /// <summary>
    /// Generates a unique request URI by appending a securely generated random string to a predefined URN prefix.
    /// </summary>
    /// <returns>A new unique URI for an authorization request.</returns>
    public Uri GenerateRequestUri()
    {
        var randomBytes = CryptoRandom.GetRandomBytes(options.Value.RequestUriLength);
        return new(RequestUrn.Prefix + Base64Url.EncodeToString(randomBytes));
    }
}
