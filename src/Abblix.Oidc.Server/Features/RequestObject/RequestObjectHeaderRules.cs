// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens.Validation;

namespace Abblix.Oidc.Server.Features.RequestObject;

/// <summary>
/// What the header of a validated request object has to say: that it is a request object, and that it is signed when
/// its client committed to signing them.
/// </summary>
internal static class RequestObjectHeaderRules
{
    /// <summary>
    /// Why the validated request object is refused for its header, or null when it is not.
    /// </summary>
    /// <param name="token">The validated request object.</param>
    /// <param name="client">The client the request object speaks for.</param>
    /// <param name="profile">The controls that client is held to.</param>
    public static string? WhyRefused(JsonWebToken token, ClientInfo client, SecurityProfileRequirements profile)
    {
        // A request object carries authorization request parameters; it is not a token. RFC 9101 section 4
        // names its media type as "application/oauth-authz-req+jwt" while noting that "some existing
        // deployments may alternatively be using the type application/jwt", so the exact value cannot
        // be demanded of a conformant client. What can be refused is a JWT declaring itself some
        // other type this class names, which is one being replayed where request parameters belong -
        // the confusion RFC 8725 section 3.11 describes. The client signs this one, so the kinds within its
        // reach are not only the ones this server issued.
        var tokenType = token.Header.Type;
        if (!JwtTypes.IsPermitted(tokenType, JsonWebTokenTypes.RequestObject))
            return $"A token of type '{tokenType}' cannot be used as a request object";

        // RFC 9101 section 10.5: a client registered with require_signed_request_object committed
        // to SIGNED request objects - an unsigned (alg=none) object satisfies the
        // structural check but not the commitment. A profile requiring signed request objects
        // (FAPI 1.0 Part 2 section 5.2.2) commits the client the same way.
        if ((client.RequireSignedRequestObject || profile.RequireSignedRequestObject) && UnsecuredToken.Is(token))
            return "The client is required to sign its request objects";

        return null;
    }
}
