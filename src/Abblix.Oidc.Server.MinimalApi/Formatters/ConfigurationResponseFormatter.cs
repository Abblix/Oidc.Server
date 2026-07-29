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

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using EndpointResponse = Abblix.Oidc.Server.Endpoints.Configuration.Interfaces.ConfigurationResponse;
using ModelResponse = Abblix.Oidc.Server.Model.ConfigurationResponse;

using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Builds the OpenID Connect discovery document by enriching the core metadata with endpoint URLs resolved from the
/// configured route templates and the current request's base URL, then returns it as a JSON <see cref="IResult"/>.
/// </summary>
public class ConfigurationResponseFormatter(
    IOptionsSnapshot<OidcOptions> options,
    IHttpContextAccessor httpContextAccessor,
    LinkGenerator linkGenerator,
    ISignedMetadataProvider signedMetadataProvider) : IConfigurationResponseFormatter
{
    /// <inheritdoc />
    public async Task<IResult> FormatResponseAsync(EndpointResponse response)
    {
        var tokenEndpoint = Resolve(EndpointNames.Token, OidcEndpoints.Token);
        var revocationEndpoint = Resolve(EndpointNames.Revocation, OidcEndpoints.Revocation);
        var introspectionEndpoint = Resolve(EndpointNames.Introspection, OidcEndpoints.Introspection);
        var userInfoEndpoint = Resolve(EndpointNames.UserInfo, OidcEndpoints.UserInfo);

        var modelResponse = new ModelResponse
        {
            Issuer = response.Issuer,

            JwksUri = Resolve(EndpointNames.Keys, OidcEndpoints.Keys),

            AuthorizationEndpoint = Resolve(EndpointNames.Authorize, OidcEndpoints.Authorize),
            UserInfoEndpoint = userInfoEndpoint,
            EndSessionEndpoint = Resolve(EndpointNames.EndSession, OidcEndpoints.EndSession),
            CheckSessionIframe = Resolve(EndpointNames.CheckSession, OidcEndpoints.CheckSession),
            PushedAuthorizationRequestEndpoint = Resolve(EndpointNames.PushedAuthorizationRequest, OidcEndpoints.PushedAuthorizationRequest),

            TokenEndpoint = tokenEndpoint,
            RevocationEndpoint = revocationEndpoint,
            IntrospectionEndpoint = introspectionEndpoint,

            RegistrationEndpoint = Resolve(EndpointNames.Register, OidcEndpoints.RegisterClient),

            BackChannelAuthenticationEndpoint = Resolve(EndpointNames.BackChannelAuthentication, OidcEndpoints.BackChannelAuthentication),

            DeviceAuthorizationEndpoint = Resolve(EndpointNames.DeviceAuthorization, OidcEndpoints.DeviceAuthorization),

            FrontChannelLogoutSupported = response.FrontChannelLogoutSupported,
            FrontChannelLogoutSessionSupported = response.FrontChannelLogoutSessionSupported,
            BackChannelLogoutSupported = response.BackChannelLogoutSupported,
            BackChannelLogoutSessionSupported = response.BackChannelLogoutSessionSupported,

            ClaimsParameterSupported = response.ClaimsParameterSupported,

            ScopesSupported = response.ScopesSupported,
            ClaimsSupported = response.ClaimsSupported,

            GrantTypesSupported = response.GrantTypesSupported,
            ResponseTypesSupported = response.ResponseTypesSupported,
            ResponseModesSupported = response.ResponseModesSupported,

            TokenEndpointAuthMethodsSupported = response.TokenEndpointAuthMethodsSupported,
            TokenEndpointAuthSigningAlgValuesSupported = response.TokenEndpointAuthSigningAlgValuesSupported,
            TlsClientCertificateBoundAccessTokens = response.TlsClientCertificateBoundAccessTokens,

            IdTokenSigningAlgValuesSupported = response.IdTokenSigningAlgValuesSupported,
            SubjectTypesSupported = response.SubjectTypesSupported,
            CodeChallengeMethodsSupported = response.CodeChallengeMethodsSupported,
            PromptValuesSupported = response.PromptValuesSupported,

            RequestParameterSupported = response.RequestParameterSupported,
            RequestObjectSigningAlgValuesSupported = response.RequestObjectSigningAlgValuesSupported,
            RequestObjectEncryptionAlgValuesSupported = response.RequestObjectEncryptionAlgValuesSupported,
            RequestObjectEncryptionEncValuesSupported = response.RequestObjectEncryptionEncValuesSupported,
            AuthorizationSigningAlgValuesSupported = response.AuthorizationSigningAlgValuesSupported,
            AuthorizationEncryptionAlgValuesSupported = response.AuthorizationEncryptionAlgValuesSupported,
            AuthorizationEncryptionEncValuesSupported = response.AuthorizationEncryptionEncValuesSupported,

            IntrospectionSigningAlgValuesSupported = response.IntrospectionSigningAlgValuesSupported,
            IntrospectionEncryptionAlgValuesSupported = response.IntrospectionEncryptionAlgValuesSupported,
            IntrospectionEncryptionEncValuesSupported = response.IntrospectionEncryptionEncValuesSupported,

            RequirePushedAuthorizationRequests = response.RequirePushedAuthorizationRequests,
            RequireSignedRequestObject = response.RequireSignedRequestObject,

            UserInfoSigningAlgValuesSupported = response.UserInfoSigningAlgValuesSupported,
            DpopSigningAlgValuesSupported = response.DpopSigningAlgValuesSupported,

            BackChannelTokenDeliveryModesSupported = response.BackChannelTokenDeliveryModesSupported,
            BackChannelAuthenticationRequestSigningAlgValuesSupported = response.BackChannelAuthenticationRequestSigningAlgValuesSupported,
            BackChannelUserCodeParameterSupported = response.BackChannelUserCodeParameterSupported,

            AcrValuesSupported = response.AcrValuesSupported,

            AuthorizationResponseIssParameterSupported = response.AuthorizationResponseIssParameterSupported,

            AuthorizationDetailsTypesSupported = response.AuthorizationDetailsTypesSupported,
        };

        var mtlsOptions = options.Value.Discovery.MtlsEndpointAliases;
        var mtlsBaseUri = options.Value.Discovery.MtlsBaseUri;

        if (mtlsOptions != null || mtlsBaseUri != null)
        {
            modelResponse = modelResponse with
            {
                MtlsEndpointAliases = new Abblix.Oidc.Server.Model.MtlsAliases
                {
                    TokenEndpoint = mtlsOptions?.TokenEndpoint ?? Rebase(tokenEndpoint, mtlsBaseUri),
                    RevocationEndpoint = mtlsOptions?.RevocationEndpoint ?? Rebase(revocationEndpoint, mtlsBaseUri),
                    IntrospectionEndpoint = mtlsOptions?.IntrospectionEndpoint ?? Rebase(introspectionEndpoint, mtlsBaseUri),
                    UserInfoEndpoint = mtlsOptions?.UserInfoEndpoint ?? Rebase(userInfoEndpoint, mtlsBaseUri),
                }
            };
        }

        if (options.Value.Discovery.SignedMetadata)
        {
            modelResponse = modelResponse with { SignedMetadata = await signedMetadataProvider.SignAsync(modelResponse) };
        }

        return Results.Json(modelResponse);
    }

    /// <summary>
    /// Resolves the absolute URL for a named endpoint if endpoint path discovery is enabled and the endpoint is
    /// active. Resolves through <see cref="LinkGenerator"/> so the URL carries any MapOidcEndpoints group prefix and
    /// the request's PathBase — the Minimal API counterpart of the MVC adapter's IUriResolver route resolution.
    /// </summary>
    private Uri? Resolve(string endpointName, OidcEndpoints enablingFlag)
    {
        if (!options.Value.Discovery.AllowEndpointPathsDiscovery ||
            !options.Value.EnabledEndpoints.HasFlag(enablingFlag))
            return null;

        var httpContext = httpContextAccessor.HttpContext.NotNull(nameof(HttpContext));
        var url = linkGenerator.GetUriByName(httpContext, endpointName, values: null);
        return url is null ? null : new Uri(url, UriKind.Absolute);
    }

    /// <summary>
    /// Rebases an original URI onto a different base URI, preserving the original's path. Used to generate mTLS
    /// endpoint aliases with an alternative base URL.
    /// </summary>
    private static Uri? Rebase(Uri? original, Uri? baseUri)
    {
        if (baseUri == null)
            return original;

        if (original == null)
            return null;

        var basePath = baseUri.AbsolutePath.TrimEnd('/');
        var origPath = original.AbsolutePath.TrimStart('/');

        var ub = new System.UriBuilder(baseUri)
        {
            Path = string.IsNullOrEmpty(basePath) || basePath == "/"
                ? $"/{origPath}"
                : $"{basePath}/{origPath}",
        };
        return ub.Uri;
    }
}
