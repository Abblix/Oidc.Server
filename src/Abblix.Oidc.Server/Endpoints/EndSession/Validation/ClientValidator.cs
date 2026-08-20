// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
public partial class ClientValidator(
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
            LogClientNotFound(context.ClientId);
            return new OidcError(
                ErrorCodes.UnauthorizedClient,
                "The client is not authorized");
        }

        context.ClientInfo = clientInfo;
        return null;
    }
}
