// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints;
using Abblix.Oidc.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

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
            .AddEndpoints()
            .AddFeatures();
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
			.AddStorages();
	}

	/// <summary>
	/// Configures the service collection with a comprehensive suite of endpoints necessary for handling various
	/// OAuth 2.0 and OpenID Connect flows, including authorization, token issuance, revocation, introspection,
	/// user information, session management and dynamic client registration.
	/// </summary>
	/// <remarks>
	/// By calling this method, the application integrates support for:
	///
	/// - The Authorization Endpoint for initiating user authentication and consent.
	/// - Pushed Authorization Request (PAR) Endpoint for pre-registering authorization requests.
	/// - Token Endpoint for issuing tokens following successful authentication.
	/// - Revocation Endpoint for token revocation by clients.
	/// - Introspection Endpoint for token validation by resource servers.
	/// - User Info Endpoint for accessing authenticated user information.
	/// - End Session Endpoint for managing user logout processes.
	/// - Back Channel Authentication Endpoint for supporting CIBA (Client Initiated Backchannel Authentication).
	/// - Check Session Endpoint for session state management in browser clients.
	/// - Dynamic Client Registration Endpoint for runtime registration of new clients.
	///
	/// This setup ensures the application is equipped to support a wide range of authentication, authorization
	/// and session management scenarios in a secure and standards-compliant manner.
	/// </remarks>
	/// <param name="services">The <see cref="IServiceCollection"/> to configure with necessary endpoints.</param>
	/// <returns>The configured <see cref="IServiceCollection"/>, enabling further service registration chaining.</returns>
	public static IServiceCollection AddEndpoints(this IServiceCollection services)
	{
		return services
			.AddAuthorizationEndpoint()
			.AddPushedAuthorizationEndpoint()
			.AddTokenEndpoint()
			.AddRevocationEndpoint()
			.AddIntrospectionEndpoint()
			.AddUserInfoEndpoint()
			.AddEndSessionEndpoint()
			.AddBackChannelAuthenticationEndpoint()
			.AddCheckSessionEndpoint()
			.AddDynamicClientEndpoints(sp => sp.GetRequiredService<IOptions<OidcOptions>>().Value.NewClientOptions);
	}
}
