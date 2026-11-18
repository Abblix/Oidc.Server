// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;

/// <summary>
/// What an accepted RP-initiated logout request leads to: the logout itself
/// (<see cref="EndSessionSuccess"/>), or the question the end user has to answer first
/// (<see cref="ConfirmationRequired"/>).
/// </summary>
/// <remarks>
/// The two travel on the same side of the result because neither is a refusal: a request that needs the end
/// user's answer is one this server intends to honour once it has one. The authorization endpoint answers the
/// same way, with <see cref="Authorization.Interfaces.InteractionRequired"/> beside its successes. The two
/// outcomes share no data, so this is an interface rather than a base record.
/// </remarks>
public interface IEndSessionResponse;
