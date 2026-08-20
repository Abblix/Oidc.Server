// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
/// <param name="logger">Logger used for warnings about register/update conflicts.</param>
/// <param name="clientInfoProvider">Store consulted to check for existing client records.</param>
public partial class ClientIdValidator(
    ILogger<ClientIdValidator> logger,
    IClientInfoProvider clientInfoProvider) : IClientRegistrationContextValidator
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
                LogClientNotFound(clientId);
                return ErrorFactory.InvalidClientMetadata($"The client with id={clientId} does not exist");

            case DynamicClientOperation.Register:
                LogClientAlreadyRegistered(clientId);
                return ErrorFactory.InvalidClientMetadata($"The client with id={clientId} is already registered");

            default:
                throw new InvalidOperationException($"Unsupported dynamic client operation: {context.Operation}");
        }
        return null;
    }
}
