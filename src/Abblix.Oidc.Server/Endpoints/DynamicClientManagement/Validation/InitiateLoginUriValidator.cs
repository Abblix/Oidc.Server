// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates the OIDC DCR 1.0 §2 <c>initiate_login_uri</c>: when supplied it must be an
/// absolute URI using the <c>https</c> scheme.
/// </summary>
public class InitiateLoginUriValidator: SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Returns an <c>invalid_client_metadata</c> error if <c>initiate_login_uri</c> is relative
    /// or non-HTTPS; <c>null</c> when absent or compliant.
    /// </summary>
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var model = context.Request;
        if (model.InitiateLoginUri != null)
        {
            if (!model.InitiateLoginUri.IsAbsoluteUri)
            {
                return ErrorFactory.InvalidClientMetadata($"The {Parameters.InitiateLoginUri} is not an absolute URI");
            }

            if (model.InitiateLoginUri.Scheme != Uri.UriSchemeHttps)
            {
                return ErrorFactory.InvalidClientMetadata($"The {Parameters.InitiateLoginUri} must have HTTPS scheme");
            }
        }

        return null;
    }
}
