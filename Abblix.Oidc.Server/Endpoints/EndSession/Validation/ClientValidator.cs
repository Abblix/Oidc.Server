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
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.EndSession.Validation;

/// <summary>
/// Resolves the client referenced by the request (either via <c>client_id</c> directly or via
/// <c>id_token_hint</c>'s audience) into a <see cref="ClientInfo"/> stored on the context for
/// later steps such as post-logout redirect URI validation. A request with no client identifier
/// at all is permitted to pass; an identifier that does not resolve yields
/// <see cref="ErrorCodes.UnauthorizedClient"/>.
/// </summary>
public class ClientValidator(
    ILogger<ClientValidator> logger,
    IClientInfoProvider clientInfoProvider) : IEndSessionContextValidator
{
    /// <inheritdoc />
    public async Task<OidcError?> ValidateAsync(EndSessionValidationContext context)
    {
        if (!context.ClientId.HasValue())
            return null;

        var clientInfo = await clientInfoProvider.TryFindClientAsync(context.ClientId).WithLicenseCheck();
        if (clientInfo == null)
        {
            logger.LogWarning("The client with id {ClientId} was not found", Sanitized.Value(context.ClientId));
            return new OidcError(
                ErrorCodes.UnauthorizedClient,
                "The client is not authorized");
        }

        context.ClientInfo = clientInfo;
        return null;
    }
}
