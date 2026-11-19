// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Abblix.Oidc.Server.Common.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using EndpointResponse = Abblix.Oidc.Server.Endpoints.Configuration.Interfaces.ConfigurationResponse;
using ModelResponse = Abblix.Oidc.Server.Model.ConfigurationResponse;

using Abblix.Oidc.Server.AspNetCore.Formatters;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Builds the OpenID Connect discovery document by enriching the core metadata with endpoint URLs, each the path
/// <see cref="IOidcEndpointResolver"/> resolves the endpoint at on the tenant's issuer authority, taken from
/// <see cref="TenantEndpointAddresses.Published"/>, then returns it as a JSON <see cref="IResult"/>.
/// </summary>
public class ConfigurationResponseFormatter(
    IOptionsSnapshot<OidcOptions> options,
    IHttpContextAccessor httpContextAccessor,
    LinkGenerator linkGenerator,
    ISignedMetadataProvider signedMetadataProvider,
    ITenantAccessor tenantAccessor) : IConfigurationResponseFormatter<IResult>
{
    /// <inheritdoc />
    public async Task<IResult> FormatResponseAsync(EndpointResponse response)
    {
        var tokenEndpoint = Resolve(OidcEndpoints.Token);
        var revocationEndpoint = Resolve(OidcEndpoints.Revocation);
        var introspectionEndpoint = Resolve(OidcEndpoints.Introspection);
        var userInfoEndpoint = Resolve(OidcEndpoints.UserInfo);

        var modelResponse = new ModelResponse
        {
            Issuer = response.Issuer.OriginalString,

            JwksUri = Resolve(OidcEndpoints.Keys),

            AuthorizationEndpoint = Resolve(OidcEndpoints.Authorize),
            UserInfoEndpoint = userInfoEndpoint,
            EndSessionEndpoint = Resolve(OidcEndpoints.EndSession),
            CheckSessionIframe = Resolve(OidcEndpoints.CheckSession),
            PushedAuthorizationRequestEndpoint = Resolve(OidcEndpoints.PushedAuthorizationRequest),

            TokenEndpoint = tokenEndpoint,
            RevocationEndpoint = revocationEndpoint,
            IntrospectionEndpoint = introspectionEndpoint,

            RegistrationEndpoint = Resolve(OidcEndpoints.RegisterClient),

            BackChannelAuthenticationEndpoint = Resolve(OidcEndpoints.BackChannelAuthentication),

            DeviceAuthorizationEndpoint = Resolve(OidcEndpoints.DeviceAuthorization),

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
#pragma warning disable ABX9001 // The flag of the experimental Client ID Metadata Documents, copied onto the wire
            ClientIdMetadataDocumentSupported = response.ClientIdMetadataDocumentSupported,
#pragma warning restore ABX9001
        };

        modelResponse = MtlsEndpointAliasing.WithMtlsAliases(modelResponse, tenantAccessor.CurrentTenant());

        if (options.Value.Discovery.SignedMetadata)
        {
            modelResponse = modelResponse with { SignedMetadata = await signedMetadataProvider.SignAsync(tenantAccessor.CurrentTenant(), modelResponse) };
        }

        return Results.Json(modelResponse);
    }

    /// <summary>
    /// The address of <paramref name="endpoint"/> if endpoint path discovery is enabled and the endpoint is active:
    /// the path the endpoint resolver answers, the one the JWT bearer grant and client authentication read, with its
    /// address taken from <see cref="TenantEndpointAddresses.Published"/>.
    /// </summary>
    /// <remarks>
    /// The resolver is the request's own, since it is scoped; a host that registered none is answered by the default
    /// one over the same link generator.
    /// </remarks>
    private Uri? Resolve(OidcEndpoints endpoint)
    {
        if (!options.Value.Discovery.AllowEndpointPathsDiscovery ||
            !options.Value.EnabledEndpoints.HasFlag(endpoint))
            return null;

        var httpContext = httpContextAccessor.HttpContext.NotNull(nameof(HttpContext));
        var resolver = httpContext.RequestServices.GetService<IOidcEndpointResolver>() ??
                       new OidcEndpointResolver(httpContextAccessor, linkGenerator);
        return resolver.Resolve(endpoint) is { } resolved ? tenantAccessor.CurrentTenant().Published(resolved) : null;
    }
}
