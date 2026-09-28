// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token.Interfaces;

/// <summary>
/// Processes incoming token requests from clients, ensuring they are valid and authorized before issuing
/// the appropriate token response. Depending on the request type and granted permissions, the response can include
/// various types of tokens such as Access Tokens, Refresh Tokens and ID Tokens.
/// </summary>
/// <remarks>
/// This interface abstracts the core logic behind token issuance in compliance with OAuth 2.0 and OpenID Connect
/// standards. Implementations are responsible for validating the token request details, determining the types of tokens
/// to issue based on the request's scope and authorization, and generating a token response that conforms to
/// the protocol specifications. While the typical response includes an Access Token and, in the case of OpenID Connect,
/// an ID Token, the exact contents of the response may vary based on the request parameters and server policies.
/// <para>
/// Processing takes no cancellation token, deliberately. For most grants it runs after the grant is spent or while it
/// is: a device code or a backchannel authentication request was taken from storage while the grant was resolved, an
/// authorization code is taken as processing starts, and a rotated refresh token is marked used while it runs. None of
/// that can be undone - RFC 6749 section 4.1.2 forbids a second use of a code - so abandoning past it would destroy the
/// grant and issue nothing. The grants that spend nothing, such as client credentials, lose nothing by finishing
/// either, since issuing is local work. Once reached, issuance runs to completion and a response nobody waits for is
/// discarded. An implementation that calls something taking a token passes
/// <see cref="System.Threading.CancellationToken.None"/> for the same reason.
/// </para>
/// </remarks>
public interface ITokenRequestProcessor
{
	/// <summary>
	/// Asynchronously processes a validated and authorized token request, generating a token response.
	/// </summary>
	/// <param name="request">The validated token request from the client.</param>
	/// <returns>A task that resolves to a <see cref="TokenIssued"/>, encapsulating the tokens to be issued to
	/// the client, or an <see cref="OidcError"/> if processing fails.</returns>
	Task<Result<TokenIssued, OidcError>> ProcessAsync(ValidTokenRequest request);
}
