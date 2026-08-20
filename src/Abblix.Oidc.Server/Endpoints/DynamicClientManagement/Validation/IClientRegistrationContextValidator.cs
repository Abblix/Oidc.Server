// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// One step in the client-registration validation pipeline (RFC 7591 §2 / OIDC DCR 1.0).
/// Implementations check a specific aspect of the supplied metadata (redirect URIs,
/// grant types, signing algorithms, sector identifier, software statement, etc.) and
/// either clear it or surface an <see cref="OidcError"/> for the response.
/// Aggregated by <see cref="ClientRegistrationContextValidatorComposite"/>.
/// </summary>
public interface IClientRegistrationContextValidator
{
	/// <summary>
	/// Validates the slice of registration metadata this implementation owns.
	/// May mutate <see cref="ClientRegistrationValidationContext"/> with derived values
	/// (for example the resolved sector identifier).
	/// </summary>
	/// <param name="context">The shared validation context for the current request.</param>
	/// <returns>An <see cref="OidcError"/> describing the rejection, or <c>null</c> when valid.</returns>
	Task<OidcError?> ValidateAsync(ClientRegistrationValidationContext context);
}
