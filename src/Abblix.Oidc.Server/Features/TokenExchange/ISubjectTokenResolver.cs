// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.TokenExchange;

/// <summary>
/// Resolves a wire-level <c>subject_token</c> of a specific RFC 8693 section 3 token type into a
/// portable <see cref="SubjectTokenContext"/>. One resolver per supported token type URI,
/// registered with keyed DI under the URI as key; the
/// <see cref="Endpoints.Token.Grants.TokenExchangeGrantHandler"/> dispatches by reading the
/// request's <c>subject_token_type</c> as the lookup key.
/// </summary>
/// <remarks>
/// The library ships resolvers for <c>urn:ietf:params:oauth:token-type:access_token</c>,
/// <c>:id_token</c>, <c>:jwt</c> (all backed by JWT validation), and <c>:refresh_token</c>
/// (backed by storage lookup). Hosts may register additional resolvers for token types this
/// library does not handle natively, e.g. SAML 2.0 assertions in federated scenarios -- the
/// handler picks them up automatically.
/// <para>
/// Lookup that returns no resolver for the requested key yields
/// <c>invalid_request</c> at the handler level -- the library never silently accepts an
/// unknown subject_token_type.
/// </para>
/// </remarks>
public interface ISubjectTokenResolver
{
    /// <summary>
    /// Parses or looks up the wire-level <paramref name="subjectToken"/> and returns the
    /// portable subject context on success, or an <see cref="OidcError"/> on failure.
    /// </summary>
    /// <param name="subjectToken">The exact <c>subject_token</c> string from the wire.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The resolved subject context on success; an OIDC error describing the
    /// rejection reason on failure. The handler maps every failure to wire-level
    /// <c>invalid_request</c> per RFC 8693 section 2.2.2.</returns>
    Task<Result<SubjectTokenContext, OidcError>> ResolveAsync(
        string subjectToken,
        CancellationToken cancellationToken);
}
