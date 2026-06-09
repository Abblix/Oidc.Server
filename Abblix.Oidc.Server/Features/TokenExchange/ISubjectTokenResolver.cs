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
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.TokenExchange;

/// <summary>
/// Resolves a wire-level <c>subject_token</c> of a specific RFC 8693 §3 token type into a
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
    /// <c>invalid_request</c> per RFC 8693 §2.2.2.</returns>
    Task<Result<SubjectTokenContext, OidcError>> ResolveAsync(
        string subjectToken,
        CancellationToken cancellationToken);
}
