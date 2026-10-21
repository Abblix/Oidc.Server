// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Consents;

/// <summary>
/// The host chooses how end-user consent is obtained, and a host that chose nothing does not start: the server
/// grants nothing it was not told to. The server is registered whole, as a host registers it, so a default provider
/// put back anywhere in its registration fails these tests.
/// </summary>
public class ConsentProviderChoiceTests
{
	private const string Server = "server";
	private const string HostProvider = "host provider";
	private const string GrantEverything = "grant everything";

	private static ServiceCollection Register(params string[] steps) => Register(hostProvider: null, steps);

	private static ServiceCollection Register(IUserConsentsProvider? hostProvider, params string[] steps)
	{
		var services = new ServiceCollection();
		services.AddLogging();
		services.AddDistributedMemoryCache();
		foreach (var step in steps)
		{
			switch (step)
			{
				case Server:
					services.AddOidcCore(options =>
					{
						options.Tenants.Add(new TenantDefinition { Id = TestIssuer.TenantId, Issuer = TestConstants.DefaultIssuer, SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)] });
					});
					break;

				case HostProvider:
					services.AddSingleton(hostProvider ?? throw new ArgumentNullException(nameof(hostProvider)));
					break;

				case GrantEverything:
					services.AddConsentGrantedForEveryClient();
					break;

				default:
					throw new ArgumentOutOfRangeException(nameof(steps), step, null);
			}
		}

		return services;
	}

	private static Task StartAsync(ServiceProvider provider)
		=> provider.GetRequiredService<IAsyncStartupValidator>().ValidateAsync(TestContext.Current.CancellationToken);

	[Fact]
	public async Task AHostChoosingNothing_DoesNotStart_AndIsToldBothChoices()
	{
		using var provider = Register(Server).BuildServiceProvider();

		var error = await Assert.ThrowsAsync<OptionsValidationException>(() => StartAsync(provider));

		// Only the names of what the host can write are asserted, which the compiler keeps honest
		var failure = Assert.Single(error.Failures);
		Assert.Contains(nameof(IUserConsentsProvider), failure);
		Assert.Contains(nameof(ConsentsServiceCollectionExtensions.AddConsentGrantedForEveryClient), failure);
	}

	/// <summary>
	/// A container that cannot say whether a provider is registered is not refused on a question it cannot be asked.
	/// </summary>
	[Fact]
	public void AContainerThatCannotAnswer_IsNotRefused()
	{
		var services = new ServiceCollection();
		services.AddConsentProviderChoice();
		var container = new Mock<IServiceProvider>();
		container.Setup(provider => provider.GetService(typeof(IServiceProvider))).Returns(() => container.Object);
		var configure = services.Single(descriptor => descriptor.ServiceType == typeof(IConfigureOptions<ConsentProviderChoice>));
		var choice = new ConsentProviderChoice();

		((IConfigureOptions<ConsentProviderChoice>)configure.ImplementationFactory!(container.Object)).Configure(choice);

		Assert.True(choice.ProviderRegistered);
	}

	[Theory]
	[InlineData(Server, GrantEverything)]
	[InlineData(GrantEverything, Server)]
	public async Task AHostGrantingEveryClientEverything_Starts_OnTheProviderGrantingIt(params string[] steps)
	{
		using var provider = Register(steps).BuildServiceProvider();

		await StartAsync(provider);

		Assert.IsType<NullConsentService>(provider.GetRequiredService<IUserConsentsProvider>());
	}

	/// <summary>
	/// A host's own provider, registered with <c>Add*</c>, is found whether it is registered before or after the
	/// server's registration, and wins over granting everything whichever of the two comes first.
	/// </summary>
	[Theory]
	[InlineData(Server, HostProvider)]
	[InlineData(HostProvider, Server)]
	[InlineData(Server, HostProvider, GrantEverything)]
	[InlineData(Server, GrantEverything, HostProvider)]
	[InlineData(GrantEverything, HostProvider, Server)]
	public async Task AHostRegisteringItsOwnProvider_Starts_OnThatProvider(params string[] steps)
	{
		var hostProvider = Mock.Of<IUserConsentsProvider>();
		using var provider = Register(hostProvider, steps).BuildServiceProvider();

		await StartAsync(provider);

		Assert.Same(hostProvider, provider.GetRequiredService<IUserConsentsProvider>());
	}
}
