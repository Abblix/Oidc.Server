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
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Cross-checks the supplied <c>client_id</c> against the operation type:
/// for <see cref="DynamicClientOperation.Update"/> (RFC 7592 §2.2) the client must already exist,
/// for <see cref="DynamicClientOperation.Register"/> (RFC 7591 §3) it must not.
/// A missing <c>client_id</c> is treated as new-registration with server-assigned id.
/// </summary>
/// <param name="clientInfoProvider">Store consulted to check for existing client records.</param>
/// <param name="logger">Logger used for warnings about register/update conflicts.</param>
public class ClientIdValidator(
    IClientInfoProvider clientInfoProvider,
    ILogger<ClientIdValidator> logger) : IClientRegistrationContextValidator
{
    /// <inheritdoc />
    public async Task<OidcError?> ValidateAsync(ClientRegistrationValidationContext context)
    {
        var clientId = context.Request.ClientId;
        if (!clientId.HasValue())
            return null;

        var clientInfo = await clientInfoProvider.TryFindClientAsync(clientId).WithLicenseCheck();
        switch (context.Operation)
        {
            // For UPDATE: client MUST exist
            case DynamicClientOperation.Update when clientInfo is not null:

            // For new registration: client must NOT exist
            case DynamicClientOperation.Register when clientInfo is null:
                break;

            case DynamicClientOperation.Update:
                logger.LogWarning("The client with id {ClientId} does not exist", Sanitized.Value(clientId));
                return ErrorFactory.InvalidClientMetadata($"The client with id={clientId} does not exist");

            case DynamicClientOperation.Register:
                logger.LogWarning("The client with id {ClientId} is already registered", Sanitized.Value(clientId));
                return ErrorFactory.InvalidClientMetadata($"The client with id={clientId} is already registered");

            default:
                throw new InvalidOperationException($"Unsupported dynamic client operation: {context.Operation}");
        }
        return null;
    }
}
