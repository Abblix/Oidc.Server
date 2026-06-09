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

namespace Abblix.Oidc.Server.Endpoints.EndSession.Validation;

/// <summary>
/// One step in the end-session validation pipeline. Each implementation inspects (and may
/// enrich) a shared <see cref="EndSessionValidationContext"/>; returning a non-null
/// <see cref="OidcError"/> aborts the pipeline. Implementations are composed via
/// <see cref="EndSessionContextValidatorComposite"/>.
/// </summary>
public interface IEndSessionContextValidator
{
	/// <summary>
	/// Performs this validator's check against the shared context.
	/// </summary>
	/// <param name="context">
	/// Mutable validation context shared with subsequent steps; this validator may
	/// populate fields (such as resolved <c>ClientInfo</c> or parsed <c>id_token_hint</c>).
	/// </param>
	/// <returns>
	/// <c>null</c> if the request passes this step, otherwise the error to surface.
	/// </returns>
	Task<OidcError?> ValidateAsync(EndSessionValidationContext context);
}
