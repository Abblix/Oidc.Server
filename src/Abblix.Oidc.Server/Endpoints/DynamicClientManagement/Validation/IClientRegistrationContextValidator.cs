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
