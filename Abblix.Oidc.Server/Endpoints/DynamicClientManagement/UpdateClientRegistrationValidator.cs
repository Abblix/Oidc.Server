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
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Validates client registration requests for UPDATE operations per RFC 7592.
/// Uses the same validation pipeline as registration but sets Operation to Update.
/// </summary>
/// <param name="validator">The client registration context validator.</param>
public class UpdateClientRegistrationValidator(IClientRegistrationContextValidator validator)
	: IRegisterClientRequestValidator
{
	/// <summary>
	/// Validates a client registration request for UPDATE operation.
	/// </summary>
	/// <param name="request">The client registration request to validate.</param>
	/// <returns>A task representing the asynchronous operation. The task result contains the validation result.</returns>
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
