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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Validates the scopes specified in the OAuth 2.0 authorization request.
/// This class checks if the requested scopes are permissible based on the client's
/// configuration and the OAuth flow type in use. It ensures that only allowed scopes
/// are requested, enhancing security and compliance with the defined authorization policies.
/// </summary>
public class ScopeValidator : SyncAuthorizationContextValidatorBase
{
	/// <summary>
	/// Validates the scopes specified in the authorization request.
	/// It checks the compatibility of requested scopes with the client's allowed scopes
	/// and the OAuth flow type. For instance, it validates if offline access is requested
	/// appropriately and if the client is authorized for such access.
	/// </summary>
	/// <param name="context">The validation context containing client information and request details.</param>
	/// <returns>
	/// An <see cref="AuthorizationRequestValidationError" /> if the scope validation fails,
	/// or null if the scopes in the request are valid.
	/// </returns>
	protected override AuthorizationRequestValidationError? Validate(AuthorizationValidationContext context)
    {
        if (context.Request.Scope.HasFlag(Scopes.OfflineAccess))
        {
            if (context.FlowType == FlowTypes.Implicit)
                return context.InvalidRequest("It is not allowed to request for offline access in implicit flow");

            if (context.ClientInfo.OfflineAccessAllowed != true)
                return context.InvalidRequest("This client is not allowed to request for offline access");
        }

        return null;
    }
}
