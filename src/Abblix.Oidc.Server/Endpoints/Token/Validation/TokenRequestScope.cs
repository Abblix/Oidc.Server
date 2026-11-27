// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// The scope a token request is served with, read by every step that judges or acts on it, so each sees the same
/// scope whether the request named it or was given the client's default.
/// </summary>
internal static class TokenRequestScope
{
    /// <summary>
    /// The scope <paramref name="context"/>'s request is served with, or null when its client is required to name
    /// one and it names none.
    /// </summary>
    /// <remarks>
    /// Only a grant starting from the client alone serves a request naming no scope with the client's default: a
    /// code, a refresh token, a device code or a backchannel request carries the scope it was granted, and a token
    /// exchange inherits the subject token's. Such a grant ignores an offline_access the client may not receive a
    /// refresh token for (<see cref="Features.ClientInformation.ClientInfo.ReceivableScopeServedFor"/>), as a device
    /// authorization or a backchannel authentication request does. A device code or a backchannel request is redeemed
    /// by a token request defining no scope (RFC 8628 section 3.4, CIBA Core 1.0 section 10.1), so a scope it names is
    /// an unrecognized parameter the server ignores (RFC 6749 section 3.2) and never refuses the code it spends. Read
    /// once the client is known.
    /// </remarks>
    public static string[]? ServedFor(TokenValidationContext context)
        => ServedFor(context.Request, () => context.ClientInfo);

    /// <summary>
    /// The scope <paramref name="request"/> was served with while it was validated.
    /// </summary>
    public static string[]? ServedFor(ValidTokenRequest request)
        => ServedFor(request.Model, () => request.ClientInfo);

    /// <remarks>The client is read only for a grant serving its default, the others carrying their own scope.
    /// </remarks>
    private static string[]? ServedFor(TokenRequest request, Func<ClientInfo> clientInfo) => request.GrantType switch
    {
        GrantTypes.ClientCredentials or GrantTypes.Password or GrantTypes.JwtBearer
            => clientInfo().ReceivableScopeServedFor(request.Scope),
        GrantTypes.DeviceAuthorization or GrantTypes.Ciba => [],
        _ => request.Scope,
    };

    /// <summary>
    /// The scope a token carries of <paramref name="granted"/> when its request is served with
    /// <paramref name="served"/>: those of the granted scopes the request names, or all of them when it names none
    /// (RFC 6749 section 6).
    /// </summary>
    /// <remarks>
    /// Judged by name, since a scope only a resource declares has no definition of its own: the request was refused
    /// earlier for any name neither the tenant nor a resource it names declares. A request naming none of the granted
    /// scopes narrows to none, which <see cref="GrantNarrowingValidator"/> refuses before a token is built.
    /// </remarks>
    public static string[] Narrow(string[] granted, string[]? served)
        => served is { Length: > 0 }
            ? [.. granted.Intersect(served, StringComparer.Ordinal)]
            : granted;
}
