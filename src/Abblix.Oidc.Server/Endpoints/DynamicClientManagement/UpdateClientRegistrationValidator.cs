// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Variant of <see cref="RegisterClientRequestValidator"/> used by the RFC 7592 §2.2 update flow.
/// Wraps the request in a <see cref="ClientRegistrationValidationContext"/> with
/// <see cref="DynamicClientOperation.Update"/> so steps such as <c>ClientIdValidator</c>
/// require the client to already exist instead of forbidding it.
/// </summary>
/// <param name="validator">Composite validator for the metadata pipeline.</param>
public class UpdateClientRegistrationValidator(IClientRegistrationContextValidator validator)
	: IRegisterClientRequestValidator
{
	/// <inheritdoc />
	public async Task<Result<ValidClientRegistrationRequest, OidcError>> ValidateAsync(ClientRegistrationRequest request)
	{
		var context = new ClientRegistrationValidationContext(request)
		{
			Operation = DynamicClientOperation.Update
		};

		var error = await validator.ValidateAsync(context);
		if (error != null)
			return error;

		return new ValidClientRegistrationRequest(request, context.SectorIdentifier);
	}
}
