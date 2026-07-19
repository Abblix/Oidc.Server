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
