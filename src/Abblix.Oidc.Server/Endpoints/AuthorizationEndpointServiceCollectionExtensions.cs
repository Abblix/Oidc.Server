// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.PushedAuthorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using CompositeRequestFetcher = Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching.CompositeRequestFetcher;

namespace Abblix.Oidc.Server.Endpoints;

/// <summary>
/// Registers the authorization endpoint, the request fetchers it reads request objects with, the pushed
/// authorization request (PAR) endpoint and the response builders that answer it.
/// </summary>
public static class AuthorizationEndpointServiceCollectionExtensions
{
    /// <summary>
    /// Adds services and processors for handling authorization requests to the service collection.
    /// </summary>
    /// <remarks>
    /// This setup is crucial for supporting the OAuth 2.0 and OpenID Connect authorization flow,
    /// ensuring that incoming authorization requests are correctly validated and processed.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddAuthorizationEndpoint(this IServiceCollection services)
    {
        services
            .AddAuthorizationRequestFetchers()
            .AddAuthorizationContextValidators();

        services.TryAddScoped<AuthorizationHandler>();
        services.TryAddScoped<IAuthorizationRequestValidator, AuthorizationRequestValidator>();
        services.TryAddSingleton<IConsentConstraintEnforcer, ConsentConstraintEnforcer>();
        services.TryAddScoped<IAuthorizationRequestProcessor, AuthorizationRequestProcessor>();

        // Single-use PAR (RFC 9126 section 7.3): decorate the processor so a pushed request_uri is consumed once a
        // terminal success has minted a code or token. Mirrors the session-management decorator and stacks
        // with it; both act independently on a SuccessfullyAuthenticated outcome.
        services.Decorate<IAuthorizationRequestProcessor, PushedAuthorizationRequestProcessorDecorator>();

        // Response encoding (iss/scope gating + JARM packing) lives in the framework-agnostic core and
        // runs from the handler after the full processing chain. Scoped: it reads per-request issuer state.
        services.TryAddScoped<IAuthorizationResponseEncoder, AuthorizationResponseEncoder>();

        // Authorization Code Flow is registered by default. Implicit / Hybrid Flow components
        // (token, id_token response processors) are registered only when the host calls
        // EnableImplicitFlow(); without that call those response types are not in the DI graph
        // and the authorization endpoint rejects them per OAuth 2.1 (draft) deprecation guidance.
        services.AddAuthorizationResponseProcessor<AuthorizationCodeBuilder>();

        // AuthorizationHandler is no longer aliased as IGrantTypeInformer: each registered
        // IAuthorizationResponseBuilder now contributes its own grant types directly to the
        // IGrantTypeInformer set, so the IGrantTypeInformer chain stays Singleton-friendly
        // (every contributor is Singleton - no captive-dep risk for Singleton consumers).
        // TryAddAlias keeps the host-first contract on this seam (issue #226).
        return services.TryAddAlias<IAuthorizationHandler, AuthorizationHandler>();
    }

    /// <summary>
    /// Registers authorization request fetchers and related services into the provided IServiceCollection.
    /// This method adds implementations for various authorization request fetchers as singletons, ensuring
    /// that they are efficiently reused throughout the application. It also composes these fetchers into a
    /// composite fetcher to handle different types of authorization requests seamlessly.
    /// </summary>
    /// <param name="services">The IServiceCollection to which the services will be added.</param>
    /// <returns>The updated IServiceCollection with the added authorization request fetchers.</returns>
    public static IServiceCollection AddAuthorizationRequestFetchers(this IServiceCollection services)
    {
        // Add a JSON object binder as a singleton
        services.TryAddSingleton<IJsonObjectBinder, JsonSerializationBinder>();

        // Add individual authorization request fetchers as enumerable strategy set
        services.TryAddEnumerable([
            ServiceDescriptor.Scoped<IAuthorizationRequestFetcher, PushedRequestFetcher>(),
            ServiceDescriptor.Scoped<IAuthorizationRequestFetcher, RequestUriFetcher>(),
            ServiceDescriptor.Scoped<IAuthorizationRequestFetcher, Authorization.RequestFetching.RequestObjectFetchAdapter>()
        ]);

        // Compose the individual fetchers into a composite fetcher
        return services
            .Compose<IAuthorizationRequestFetcher, CompositeRequestFetcher>();
    }

    /// <summary>
    /// Registers validators and processors for pushed authorization requests (PAR), enhancing the security and
    /// efficiency of the authorization process by allowing clients to send requests directly to
    /// the authorization server via a back-channel connection.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddPushedAuthorizationEndpoint(this IServiceCollection services)
    {
        services.TryAddScoped<IPushedAuthorizationHandler>(sp => sp.CreateService<PushedAuthorizationHandler>(
            Dependency.Override<IAuthorizationRequestFetcher, Authorization.RequestFetching.RequestObjectFetchAdapter>()));
        services.TryAddScoped<IPushedAuthorizationRequestValidator, PushedAuthorizationRequestValidator>();
        services.TryAddScoped<IPushedAuthorizationRequestProcessor, PushedAuthorizationRequestProcessor>();
        return services;
    }

    /// <summary>
    /// Registers <typeparamref name="TImpl"/> as a Singleton concrete service and aliases the
    /// SAME instance under both <see cref="IAuthorizationResponseBuilder"/> (for response-type
    /// dispatch in the authorization endpoint) and <see cref="IGrantTypeInformer"/> (for
    /// discovery and registration-time gates that aggregate <c>grant_types_supported</c>).
    /// Every <see cref="IAuthorizationResponseBuilder"/> implementation must be registered
    /// through this helper so each processor's declared grant type lands in the
    /// <see cref="IGrantTypeInformer"/> chain without an extra registration step.
    /// </summary>
    /// <typeparam name="TImpl">The concrete response-builder implementation to register.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <param name="lifetime">The service lifetime for the processor and its aliases; defaults to
    /// <see cref="ServiceLifetime.Singleton"/>. Use <see cref="ServiceLifetime.Scoped"/> when the
    /// processor has scoped dependencies, to avoid a captive dependency.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddAuthorizationResponseProcessor<TImpl>(
        this IServiceCollection services,
        ServiceLifetime lifetime = ServiceLifetime.Singleton)
        where TImpl : class, IAuthorizationResponseBuilder
    {
        // The IAuthorizationResponseBuilder / IGrantTypeInformer aliases inherit this lifetime
        // (BuildAliasDescriptor preserves the source lifetime), so a builder with scoped
        // dependencies registers Scoped and its aliases follow - no captive dependency.
        services.TryAdd(new ServiceDescriptor(typeof(TImpl), typeof(TImpl), lifetime));
        services.TryAddEnumerableAlias<IAuthorizationResponseBuilder, TImpl>();
        services.TryAddEnumerableAlias<IGrantTypeInformer, TImpl>();
        return services;
    }
}
