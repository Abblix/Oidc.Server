// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.Consents;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Consents;

/// <summary>
/// The host chooses how end-user consent is obtained, and a host that chose nothing does not start: the server
/// grants nothing it was not told to.
/// </summary>
public class ConsentProviderChoiceTests
{
	private static ServiceCollection ServerServices()
	{
		var services = new ServiceCollection();
		services.AddLogging();
		services.AddCommonServices();
		return services;
	}

	private static Task StartAsync(ServiceProvider provider)
		=> provider.GetRequiredService<IAsyncStartupValidator>().ValidateAsync(TestContext.Current.CancellationToken);

	[Fact]
	public async Task AHostChoosingNothing_DoesNotStart_AndIsToldBothChoices()
	{
		using var provider = ServerServices().BuildServiceProvider();

		var error = await Assert.ThrowsAsync<OptionsValidationException>(() => StartAsync(provider));

		// Only the names of what the host can write are asserted, which the compiler keeps honest
		var failure = Assert.Single(error.Failures);
		Assert.Contains(nameof(IUserConsentsProvider), failure);
		Assert.Contains(nameof(ConsentsServiceCollectionExtensions.AddConsentGrantedForEveryClient), failure);
	}

	[Fact]
	public async Task AHostGrantingEveryClientEverything_Starts_OnTheProviderGrantingIt()
	{
		var services = ServerServices();
		services.AddConsentGrantedForEveryClient();
		using var provider = services.BuildServiceProvider();

		await StartAsync(provider);

		Assert.IsType<NullConsentService>(provider.GetRequiredService<IUserConsentsProvider>());
	}

	/// <summary>
	/// A host's own provider is found whether it is registered before or after the server's registration, and wins
	/// over granting everything whichever of the two comes first.
	/// </summary>
	[Theory]
	[InlineData(false, false)]
	[InlineData(true, false)]
	[InlineData(false, true)]
	public async Task AHostRegisteringItsOwnProvider_Starts_OnThatProvider(bool beforeTheServer, bool alsoGrantingEverything)
	{
		var hostProvider = new Mock<IUserConsentsProvider>().Object;
		var services = new ServiceCollection();
		services.AddLogging();
		if (beforeTheServer)
			services.AddSingleton(hostProvider);

		services.AddCommonServices();
		if (!beforeTheServer)
			services.AddSingleton(hostProvider);

		if (alsoGrantingEverything)
			services.AddConsentGrantedForEveryClient();

		using var provider = services.BuildServiceProvider();

		await StartAsync(provider);

		Assert.Same(hostProvider, provider.GetRequiredService<IUserConsentsProvider>());
	}
}
