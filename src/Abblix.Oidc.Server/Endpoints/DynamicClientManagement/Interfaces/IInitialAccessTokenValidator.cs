// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Judges the initial access token a client registration request carries (RFC 7591 section 3), from the
/// <c>Authorization</c> header alone, so a request is judged by its token whatever its body holds.
/// </summary>
public interface IInitialAccessTokenValidator
{
    /// <summary>
    /// Judges the initial access token the request carries, where the server requires one.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="authorizationHeaderLines">Every line of the request's <c>Authorization</c> header, or <c>null</c>
    /// when it carries none.</param>
    /// <returns><c>null</c> when the token passes or none is required; otherwise the refusal: a
    /// <see cref="MissingAuthenticationError"/> for a request carrying no Bearer credentials, a
    /// <see cref="BearerRequestError"/> for a malformed one, an <c>invalid_token</c> error for a token that fails.
    /// </returns>
    Task<OidcError?> ValidateAsync(TenantDefinition tenant, IReadOnlyList<string>? authorizationHeaderLines);
}
