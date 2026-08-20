// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Utils;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.EndSession;

/// <summary>
/// Top-level entry point for the OpenID Connect RP-Initiated Logout endpoint.
/// Validates the incoming request and, on success, performs sign-out and produces
/// the post-logout redirect target plus any front-channel logout URIs to be invoked
/// by the relying party.
/// </summary>
public interface IEndSessionHandler
{
    /// <summary>
    /// Handles a single RP-initiated logout request end to end.
    /// </summary>
    /// <param name="endSessionRequest">The parsed wire-level end-session request.</param>
    /// <returns>
    /// An <see cref="EndSessionSuccess"/> on success, or an <see cref="OidcError"/>
    /// describing why the request was rejected.
    /// </returns>
    Task<Result<EndSessionSuccess, OidcError>> HandleAsync(Model.EndSessionRequest endSessionRequest);
}
