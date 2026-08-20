// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Model;
using AuthorizationResponse = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse;

namespace Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;

/// <summary>
/// Successful response from the Pushed Authorization Request endpoint (RFC 9126 §2.2):
/// the opaque <c>request_uri</c> the client must echo to the authorization endpoint, and
/// the lifetime <c>expires_in</c> in seconds after which the server may discard the
/// stored request payload.
/// </summary>
public record PushedAuthorizationResponse(AuthorizationRequest Model, Uri RequestUri, TimeSpan ExpiresIn)
    : AuthorizationResponse(Model)
{
    /// <summary>
    /// RFC 9126 §2.2 <c>request_uri</c>: a one-time-use, server-generated reference to the
    /// stored authorization request, to be passed by the client on the redirect to the
    /// authorization endpoint instead of the parameters themselves.
    /// </summary>
    public Uri RequestUri { get; init; } = RequestUri;

    /// <summary>
    /// RFC 9126 §2.2 <c>expires_in</c>: lifetime of <see cref="RequestUri"/>; once it elapses
    /// the authorization server is free to invalidate the entry and reject any subsequent
    /// authorization request that references it.
    /// </summary>
    public TimeSpan ExpiresIn { get; init; } = ExpiresIn;
};
