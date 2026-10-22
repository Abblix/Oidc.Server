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
using Abblix.Oidc.Server.Features.Issuer;
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
    ISignedMetadataProvider signedMetadataProvider,
    IIssuerSettings issuerSettings) : IConfigurationResponseFormatter
{
    /// <inheritdoc />
    public async Task<IResult> FormatResponseAsync(EndpointResponse response)
    {
        var tokenEndpoint = Resolve(EndpointNames.Token, OidcEndpoints.Token, response.Issuer);
        var revocationEndpoint = Resolve(EndpointNames.Revocation, OidcEndpoints.Revocation, response.Issuer);
        var introspectionEndpoint = Resolve(EndpointNames.Introspection, OidcEndpoints.Introspection, response.Issuer);
        var userInfoEndpoint = Resolve(EndpointNames.UserInfo, OidcEndpoints.UserInfo, response.Issuer);

        var modelResponse = new ModelResponse
        {
            Issuer = response.Issuer.OriginalString,

            JwksUri = Resolve(EndpointNames.Keys, OidcEndpoints.Keys, response.Issuer),

            AuthorizationEndpoint = Resolve(EndpointNames.Authorize, OidcEndpoints.Authorize, response.Issuer),
            UserInfoEndpoint = userInfoEndpoint,
            EndSessionEndpoint = Resolve(EndpointNames.EndSession, OidcEndpoints.EndSession, response.Issuer),
            CheckSessionIframe = Resolve(EndpointNames.CheckSession, OidcEndpoints.CheckSession, response.Issuer),
            PushedAuthorizationRequestEndpoint = Resolve(EndpointNames.PushedAuthorizationRequest, OidcEndpoints.PushedAuthorizationRequest, response.Issuer),

            TokenEndpoint = tokenEndpoint,
            RevocationEndpoint = revocationEndpoint,
            IntrospectionEndpoint = introspectionEndpoint,

            RegistrationEndpoint = Resolve(EndpointNames.Register, OidcEndpoints.RegisterClient, response.Issuer),

            BackChannelAuthenticationEndpoint = Resolve(EndpointNames.BackChannelAuthentication, OidcEndpoints.BackChannelAuthentication, response.Issuer),

            DeviceAuthorizationEndpoint = Resolve(EndpointNames.DeviceAuthorization, OidcEndpoints.DeviceAuthorization, response.Issuer),

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

        modelResponse = MtlsEndpointAliasing.WithMtlsAliases(modelResponse, issuerSettings.MtlsBaseUri);

        if (options.Value.Discovery.SignedMetadata)
        {
            modelResponse = modelResponse with { SignedMetadata = await signedMetadataProvider.SignAsync(modelResponse) };
        }

        return Results.Json(modelResponse);
    }

    /// <summary>
    /// Resolves the absolute URL for a named endpoint if endpoint path discovery is enabled and the endpoint is
    /// active. Resolves through <see cref="LinkGenerator"/> so the URL carries any MapOidcEndpoints group prefix and
    /// the request's PathBase - the Minimal API counterpart of the MVC adapter's IUriResolver route resolution.
    /// </summary>
    private Uri? Resolve(string endpointName, OidcEndpoints enablingFlag, Uri issuer)
    {
        if (!options.Value.Discovery.AllowEndpointPathsDiscovery ||
            !options.Value.EnabledEndpoints.HasFlag(enablingFlag))
            return null;

        var httpContext = httpContextAccessor.HttpContext.NotNull(nameof(HttpContext));
        var url = linkGenerator.GetUriByName(httpContext, endpointName, values: null);
        return url is null ? null : MtlsEndpointAliasing.OnIssuersHost(
            new Uri(url, UriKind.Absolute), issuer, issuerSettings.MtlsBaseUri);
    }
}
