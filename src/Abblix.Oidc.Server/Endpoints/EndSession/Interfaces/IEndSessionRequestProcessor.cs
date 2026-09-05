// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;

/// <summary>
/// Performs the side-effects of RP-initiated logout once a request has been validated:
/// signs the end user out of the OP session, notifies every client that participated
/// in the session (back-channel and/or front-channel logout), and assembles the
/// post-logout redirect target.
/// </summary>
public interface IEndSessionRequestProcessor
{
	/// <summary>
	/// Executes logout for an already-validated request.
	/// </summary>
	/// <param name="request">A request that passed all validation steps.</param>
	/// <returns>
	/// An <see cref="EndSessionSuccess"/> describing the post-logout redirect and any
	/// front-channel URIs to invoke; an <see cref="OidcError"/> if processing cannot complete.
	/// </returns>
	Task<Result<EndSessionSuccess, OidcError>> ProcessAsync(ValidEndSessionRequest request);
}
