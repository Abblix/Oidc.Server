// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.Consents;

/// <summary>
/// Registers how end-user consent is obtained.
/// </summary>
public static class ConsentsServiceCollectionExtensions
{
	/// <summary>
	/// What a host is told when it chose neither its own consent provider nor granting every client everything.
	/// </summary>
	internal const string NotChosenMessage =
		$"No {nameof(IUserConsentsProvider)} is registered, so nothing decides what the end user consents to. "
		+ $"Register your own {nameof(IUserConsentsProvider)}, which obtains the end user's consent, or call "
		+ $"{nameof(AddConsentGrantedForEveryClient)}() to grant every client everything it asks for, which suits "
		+ "only a deployment whose every client is its own.";

	/// <summary>
	/// Grants every client everything it asks for, so no end user is ever asked for consent.
	/// </summary>
	/// <param name="services">The <see cref="IServiceCollection"/> to register the consent provider in.</param>
	/// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
	/// <remarks>
	/// It suits only a deployment whose every client is its own. With it, <c>prompt=none</c> never answers
	/// <c>consent_required</c> and <c>prompt=consent</c> never shows a consent page, so the end user cannot refuse
	/// what a client asks for (OpenID Connect Core 1.0, section 3.1.2.4). So a client allowed offline access only
	/// with <c>prompt=consent</c> gets a refresh token by sending it. A host serving clients it does not own
	/// registers its own <see cref="IUserConsentsProvider"/> instead, which wins over this call whichever comes
	/// first when registered with an <c>Add*</c> method; a <c>TryAdd*</c> registration after this call is skipped.
	/// <para>
	/// A server that never authorizes an end user, such as one issuing tokens only to clients themselves or serving
	/// Shared Signals alone, obtains no consent at all, and this call is the choice that says so.
	/// </para>
	/// </remarks>
	public static IServiceCollection AddConsentGrantedForEveryClient(this IServiceCollection services)
	{
		services.TryAddSingleton<IUserConsentsProvider, NullConsentService>();
		return services;
	}

	/// <summary>
	/// Arms the startup check that a host granting every client everything (<see cref="AddConsentGrantedForEveryClient"/>)
	/// lets no client in that nobody reviewed: a metadata document from any URL, or a registration nobody authorized.
	/// </summary>
	internal static IServiceCollection AddConsentForUnreviewedClientsCheck(this IServiceCollection services)
	{
		// Armed by each way a client nobody reviewed gets in, once whichever comes first
		if (services.Any(descriptor => descriptor.ServiceType == typeof(IConfigureOptions<ConsentForUnreviewedClients>)))
			return services;

		services.AddOptions<ConsentForUnreviewedClients>()
			.Configure<IOptions<OidcOptions>>((check, options) =>
			{
				var settings = options.Value;
				var grantedToEveryClient = GrantsConsentToEveryClient(services);
				check.GrantedToAnyUrl = grantedToEveryClient &&
					settings.ClientIdMetadataDocuments.Enabled &&
					OpenRegistration.AdmitsAnyDocument(settings);
				check.GrantedToAnyRegistrant = grantedToEveryClient &&
					settings.EnabledEndpoints.HasFlag(OidcEndpoints.RegisterClient) &&
					OpenRegistration.AdmitsAnyRegistrant(settings);
			})
			.Validate(check => !check.GrantedToAnyUrl, ConsentForUnreviewedClients.AnyUrlMessage)
			.Validate(check => !check.GrantedToAnyRegistrant, ConsentForUnreviewedClients.AnyRegistrantMessage)
			.ValidateOnStart();
		return services;
	}

	/// <summary>
	/// Whether the consent provider the container resolves grants every client everything it asks for.
	/// </summary>
	/// <remarks>
	/// Read from the registration the container resolves, the last one, by the type it registers, so neither the order
	/// of the host's calls nor building the provider at startup decides it. A host's own provider, or one it builds by
	/// an untyped factory, is not that one.
	/// </remarks>
	private static bool GrantsConsentToEveryClient(IServiceCollection services)
		=> services.LastOrDefault(descriptor =>
				   descriptor is { IsKeyedService: false } &&
				   descriptor.ServiceType == typeof(IUserConsentsProvider))?
			   .ResolveImplementationType() is { } implementation &&
		   typeof(NullConsentService).IsAssignableFrom(implementation);

	/// <summary>
	/// Arms the startup check that the host chose how consent is obtained: a host registering neither its own
	/// <see cref="IUserConsentsProvider"/> nor <see cref="AddConsentGrantedForEveryClient"/> does not start.
	/// </summary>
	internal static IServiceCollection AddConsentProviderChoice(this IServiceCollection services)
	{
		services.AddOptions<ConsentProviderChoice>()
			.Configure<IServiceProvider>(
				(choice, provider) => choice.ProviderRegistered =
					provider.GetService<IServiceProviderIsService>()?.IsService(typeof(IUserConsentsProvider)) ?? true)
			.Validate(choice => choice.ProviderRegistered, NotChosenMessage)
			.ValidateOnStart();
		return services;
	}
}
