// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.UserAuthentication;

/// <summary>
/// What a sign-in did to the sessions of the user agent.
/// </summary>
/// <param name="Session">
/// The session actually written, which may differ from the one passed in: a store continuing an existing session
/// keeps that session's identifier.
/// </param>
/// <param name="EndedSessions">
/// The sessions the sign-in ended, whose tokens and clients are then dealt with as on logout. Empty when the store
/// ended none, which is also the answer of a store keeping several sessions side by side.
/// </param>
public record AuthSessionSignInResult(AuthSession Session, IReadOnlyCollection<AuthSession> EndedSessions);
