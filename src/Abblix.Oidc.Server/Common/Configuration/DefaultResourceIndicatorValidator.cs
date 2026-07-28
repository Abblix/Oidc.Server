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

using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses at startup a <see cref="OidcOptions.DefaultResourceIndicator"/> that would put an unusable value in
/// every access token's <c>aud</c> claim.
/// </summary>
/// <remarks>
/// Both refusals are contradictions the host cannot see at runtime, because the token still issues and only
/// the resource server rejects it - somewhere else, later, and reported as an invalid token rather than as a
/// misconfiguration here.
/// </remarks>
public sealed class DefaultResourceIndicatorValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        if (options.DefaultResourceIndicator is not { } defaultResource)
            return ValidateOptionsResult.Success;

        // RFC 8707 Section 2 requires a resource indicator to be an absolute URI, and a relative one could
        // never match a request either, so it would sit as a value nothing accepts.
        if (!defaultResource.IsAbsoluteUri)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(OidcOptions.DefaultResourceIndicator)} '{defaultResource}' must be an absolute URI " +
                $"(RFC 8707 Section 2).");
        }

        // A default naming a resource this server does not know produces tokens whose audience no resource
        // server recognises, and the request that would have named it explicitly is refused as
        // invalid_target - so the two paths would disagree about the same identifier.
        var known = options.Resources is { Length: > 0 } resources &&
                    Array.Exists(resources, resource => resource.Resource == defaultResource);

        if (!known)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(OidcOptions.DefaultResourceIndicator)} '{defaultResource}' is not among the " +
                $"configured {nameof(OidcOptions.Resources)}. Register it there, or clear the default to keep " +
                $"the client identifier as the audience.");
        }

        return ValidateOptionsResult.Success;
    }
}
