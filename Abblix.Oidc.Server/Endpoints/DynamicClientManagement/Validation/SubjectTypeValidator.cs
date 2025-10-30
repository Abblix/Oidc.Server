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
using System.Net.Http.Json;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// This class validates the subject type in a client registration request. It checks if the subject type is pairwise,
/// and if so, verifies the sector identifier URI and its content. It also ensures that all redirect URIs use the HTTPS scheme.
/// If any validation fails, it returns a AuthError.
/// </summary>
public class SubjectTypeValidator: IClientRegistrationContextValidator
{
    /// <summary>
    /// Initializes a new instance of the SubjectTypeValidator class with the provided dependencies.
    /// </summary>
    /// <param name="httpClientFactory">The HttpClientFactory for making HTTP requests.</param>
    /// <param name="logger">The logger for logging purposes.</param>
    public SubjectTypeValidator(
        IHttpClientFactory httpClientFactory,
        ILogger<SubjectTypeValidator> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger _logger;

    /// <summary>
    /// Validates the subject type in the client registration request.
    /// </summary>
    /// <param name="context">The validation context containing client registration data.</param>
    /// <returns>
    /// A AuthError if any validation fails, or null if the request is valid.
    /// </returns>
    public async Task<AuthError?> ValidateAsync(ClientRegistrationValidationContext context)
    {
        var request = context.Request;
        if (request.SubjectType == SubjectTypes.Pairwise)
        {
            var sectorIdentifierUri = request.SectorIdentifierUri;
            if (sectorIdentifierUri != null)
            {
                if (!sectorIdentifierUri.IsAbsoluteUri)
                {
                    return ErrorFactory.InvalidClientMetadata(
                        $"{Parameters.SectorIdentifierUri} must be absolute URI");
                }
                if (sectorIdentifierUri.Scheme != Uri.UriSchemeHttps)
                {
                    return ErrorFactory.InvalidClientMetadata(
                        $"{Parameters.SectorIdentifierUri} must have {Uri.UriSchemeHttps} scheme");
                }

                Uri[]? sectorIdentifierUriContent;
                {
                    try
                    {
                        // TODO move to separate class
                        sectorIdentifierUriContent = await _httpClientFactory.CreateClient().GetFromJsonAsync<Uri[]>(
                            sectorIdentifierUri);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Unable to receive content of {SectorIdentifierUri}",
                            Sanitized.Value(sectorIdentifierUri));
                        return ErrorFactory.InvalidClientMetadata(
                            $"Unable to receive content of {Parameters.SectorIdentifierUri}");
                    }
                }

                if (sectorIdentifierUriContent is not { Length: > 0 })
                {
                    return ErrorFactory.InvalidClientMetadata(
                        $"The content of {Parameters.SectorIdentifierUri} is empty");
                }

                if (sectorIdentifierUriContent.Any(uri => uri.Scheme != Uri.UriSchemeHttps))
                {
                    return ErrorFactory.InvalidClientMetadata("All schemes in the redirect URIs must be https");
                }

                var missingUris = sectorIdentifierUriContent.Except(request.RedirectUris).ToArray();
                if (missingUris.Length > 0)
                {
                    _logger.LogWarning("The following URIs are present in the {SectorIdentifierUri}, but missing from the Redirect URIs: {@MissingUris}",
                        Sanitized.Value(sectorIdentifierUri),
                        missingUris);

                    return ErrorFactory.InvalidClientMetadata(
                        $"The content received from the {Parameters.SectorIdentifierUri} contains one or more URIs that are not in the registered list of redirect URIs");
                }

                context.SectorIdentifier = sectorIdentifierUri.Host;
            }
            else
            {
                if (request.RedirectUris.Any(uri => uri.Scheme != Uri.UriSchemeHttps))
                {
                    return ErrorFactory.InvalidClientMetadata("All schemes in the redirect URIs must be https");
                }

                var hosts = request.RedirectUris.Select(uri => uri.Host).Distinct().ToArray();
                if (hosts.Length > 1)
                {
                    return ErrorFactory.InvalidRedirectUri("The client specified pairwise subject type, but provides several redirect URIs with different hosts");
                }

                var sectorIdentifier = hosts[0];
                context.SectorIdentifier = sectorIdentifier;
            }
        }

        return null;
    }
}
