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

using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints;
using Abblix.Oidc.Server.Features;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server;

/// <summary>
/// Extension methods for integrating OpenID Connect (OIDC) core services into an application's service collection.
/// </summary>
/// <remarks>
/// These methods facilitate the setup of essential components for implementing OIDC authentication and
/// authorization flows, such as token issuance, client authentication, and session management.
/// By calling these extension methods, developers can configure and customize the OIDC server according
/// to their application's security requirements and user management policies.
/// </remarks>
public static class ServiceCollectionExtensions
{
	/// <summary>
	/// Registers the core OIDC server services and configurations into the provided service collection.
	/// </summary>
	/// <param name="services">The IServiceCollection instance to which the OIDC services are added.</param>
	/// <param name="configureOptions">A delegate to configure OIDC server options, allowing customization of settings
	/// like issuer URL, token lifetimes, and supported grant types.</param>
	/// <returns>The updated IServiceCollection instance, enabling chaining of further service registrations.</returns>
	public static IServiceCollection AddOidcCore(this IServiceCollection services, Action<OidcOptions> configureOptions)
	{
		return services.AddOidcCore((options, _) => configureOptions(options));
	}

	/// <summary>
	/// Adds OIDC server core services to the service collection with additional access to the service provider
	/// for more complex configuration scenarios.
	/// </summary>
	/// <param name="services">The IServiceCollection to enhance with OIDC services.</param>
	/// <param name="configureOptions">A delegate that configures OIDC options with access to the service provider,
	/// allowing for dynamic configurations based on other registered services.</param>
	/// <returns>The IServiceCollection enabling further configurations.</returns>
	/// <remarks>
	/// This overload provides flexibility to access other services during the OIDC configuration,
	/// such as dynamic issuer discovery or conditional service registrations based on the environment or other services.
	/// </remarks>
	public static IServiceCollection AddOidcCore(
        this IServiceCollection services,
		Action<OidcOptions, IServiceProvider> configureOptions)
	{
		return services
			.AddOptions<OidcOptions>()
			.Configure(configureOptions).Services
			.AddCommonServices()
            .AddSecureHttpFetch() // Must be before AddEndpoints() so DecorateKeyed can find it
            .AddEndpoints()
            .AddFeatures()
            .AddAuthorizationGrants(); // Compose grant handlers AFTER all handlers are registered
	}

	/// <summary>
	/// Registers a comprehensive set of services related to client authentication, information management,
	/// issuer identification, token services, JWT handling, session management, random value generation
	/// and logout notifications.
	/// </summary>
	/// <remarks>
	/// This method serves as a convenience wrapper that aggregates the registration of various foundational services
	/// necessary for the application's security and functionality.
	///
	/// It includes:
	/// - Client authentication mechanisms.
	/// - Client information management.
	/// - Issuer identification.
	/// - Token generation, validation and management services.
	/// - JSON Web Token (JWT) support.
	/// - Session management capabilities.
	/// - Random value generators for security tokens and identifiers.
	/// - Logout notification mechanisms.
	///
	/// By invoking this method, an application ensures that all critical security and operational features
	/// are configured and ready for use.
	/// </remarks>
	/// <param name="services">The <see cref="IServiceCollection"/> to configure with essential features.</param>
	/// <returns>The configured <see cref="IServiceCollection"/>, allowing for further chaining of service registrations.</returns>
	public static IServiceCollection AddFeatures(this IServiceCollection services)
	{
		return services
			.AddLicenseFromOptions()
			.AddClientAuthentication()
			.AddClientInformation()
			.AddIssuer()
			.AddTokenServices()
			.AddSessionManagement()
			.AddRandomGenerators()
			.AddLogoutNotification()
			.AddStorages()
			.AddUserInfo()
			.AddRequestObject()
			.AddDPoP()
			.AddRichAuthorizationRequests();
			// AddSecureHttpFetch() moved to AddOidcCore() to run before AddEndpoints()
	}

	/// <summary>
	/// Configures the service collection with the always-on OAuth 2.0 and OpenID Connect endpoints — the set
	/// mounted unconditionally regardless of <see cref="OidcOptions.EnabledEndpoints"/>: discovery, authorization,
	/// PAR, token, UserInfo and end session.
	/// </summary>
	/// <remarks>
	/// By calling this method, the application integrates support for:
	///
	/// - The Configuration (discovery) Endpoint for publishing provider metadata.
	/// - The Authorization Endpoint for initiating user authentication and consent.
	/// - Pushed Authorization Request (PAR) Endpoint for pre-registering authorization requests.
	/// - Token Endpoint for issuing tokens following successful authentication.
	/// - User Info Endpoint for accessing authenticated user information.
	/// - End Session Endpoint for managing user logout processes.
	///
	/// The niche or security-sensitive endpoints — Revocation, Introspection, CIBA, Check Session and Dynamic
	/// Client Registration — are not wired here. Each is opt-in through its dedicated <c>AddX()</c> feature method
	/// (<c>AddRevocation</c>, <c>AddIntrospection</c>, <c>AddBackChannelAuthentication</c>, <c>AddCheckSession</c>,
	/// <c>AddDynamicClientRegistration</c>), which registers the endpoint services and re-enables its flag in
	/// <see cref="OidcOptions.EnabledEndpoints"/> (defaulting to <see cref="OidcEndpoints.Base"/>).
	/// </remarks>
	/// <param name="services">The <see cref="IServiceCollection"/> to configure with necessary endpoints.</param>
	/// <returns>The configured <see cref="IServiceCollection"/>, enabling further service registration chaining.</returns>
	public static IServiceCollection AddEndpoints(this IServiceCollection services)
	{
		return services
			.AddConfigurationEndpoint()
			.AddAuthorizationEndpoint()
			.AddPushedAuthorizationEndpoint()
			.AddTokenEndpoint()
			.AddUserInfoEndpoint()
			.AddEndSessionEndpoint();
	}
}
