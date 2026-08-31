// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// What a CIBA push notification's ID Token must bind itself to, so the notification cannot be replayed
/// against a different request.
/// </summary>
/// <remarks>
/// Its presence is what says "this delivery is a push". CIBA Core 1.0 Section 10.3.1 requires these
/// claims in push mode and says so in as many words - "Note that these claims are only required in Push
/// mode" - so a null here is a poll or a ping, or a flow that is not CIBA at all, and those ID Tokens
/// are left exactly as they were.
/// <para>
/// The reason the mode has to be carried rather than inferred: poll and ping redeem at the token
/// endpoint with the same grant type and the same identifier, so nothing in the request itself
/// distinguishes them. Only the caller that IS the push path knows.
/// </para>
/// <para>
/// Push is also the one mode where the client never asked for these tokens by holding the identifier in
/// its own hand. A poll client sends the identifier and reads the answer to that call; a push client
/// receives an unsolicited body and has nothing tying its three parts together but this.
/// </para>
/// </remarks>
/// <param name="AuthenticationRequestId">The <c>auth_req_id</c> this delivery answers, carried into the
/// ID Token verbatim.</param>
/// <param name="RefreshToken">The refresh token travelling in the same notification, or
/// <see langword="null"/> when none is sent - in which case the specification asks for no hash.</param>
public record PushDeliveryBindings(string AuthenticationRequestId, string? RefreshToken);
