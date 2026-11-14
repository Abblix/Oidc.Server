// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

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
