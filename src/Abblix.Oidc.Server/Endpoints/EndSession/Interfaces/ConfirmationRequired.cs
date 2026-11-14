// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;

/// <summary>
/// Outcome signalling that the end user must be asked whether to log out before the request is acted upon
/// (OpenID Connect RP-Initiated Logout 1.0 section 2).
/// </summary>
/// <param name="Confirmation">The value the host's page sends back with the end user's answer, as the
/// <c>confirmation</c> parameter of the next request. It is issued by this server for the session the question is
/// about, is good for one use, and expires with <see cref="Common.Configuration.OidcOptions.LogoutConfirmationLifetime"/>.
/// </param>
/// <remarks>
/// The value is what makes the answer an answer. Section 6 of the same specification names the threat it defends
/// against: "Logout requests without a valid id_token_hint value are a potential means of denial of service;
/// therefore, OPs should obtain explicit confirmation from the End-User before acting upon them". A confirmation
/// any caller could state for itself would let a site end a session by asserting that the end user had agreed, so
/// the host renders this value into the page it shows and sends it back with the answer.
/// </remarks>
public record ConfirmationRequired(string Confirmation) : IEndSessionResponse;
