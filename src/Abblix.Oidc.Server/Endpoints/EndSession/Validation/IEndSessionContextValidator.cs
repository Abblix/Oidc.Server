// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
