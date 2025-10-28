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

using System;
using System.Collections.Generic;
using System.Linq;
using Abblix.DependencyInjection;
using Abblix.DependencyInjection.UnitTests.Model;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.DependencyInjection.UnitTests;

/// <summary>
/// Tests for the AddAlias extension method to verify same-instance resolution
/// and IEnumerable collection behavior.
/// </summary>
public class AddAliasTests
{

	/// <summary>
	/// Verifies that when multiple services are registered and aliased to different interfaces,
	/// IEnumerable resolution returns all instances in the correct order, and corresponding
	/// indices resolve to the same instance across both interface types.
	/// </summary>
	/// <remarks>
	/// This test validates that:
	/// <list type="bullet">
	/// <item>Each source service (Service, Service2) can be aliased to multiple interfaces (IPrimaryService, IBaseService)</item>
	/// <item>GetServices returns all registered instances in registration order</item>
	/// <item>The same source instance is returned when resolved through different alias interfaces (same-instance semantics)</item>
	/// <item>Instance types are preserved correctly across different interface resolutions</item>
	/// </list>
	/// </remarks>
	[Fact]
	public void AddAlias_WhenMultipleServicesAliasedToMultipleInterfaces_ReturnsMatchingInstances()
	{
		// Arrange
		var services = new ServiceCollection();

		// Register first service and create aliases for both interfaces
		services.AddScoped<ServiceA>();
		services.AddAlias<IPrimaryService, ServiceA>();
		services.AddAlias<IAliasService, ServiceA>();

		// Register second service and create aliases for both interfaces
		services.AddScoped<ServiceB>();
		services.AddAlias<IPrimaryService, ServiceB>();
		services.AddAlias<IAliasService, ServiceB>();

		var serviceProvider = services.BuildServiceProvider();

		// Act
		var primaryServices = serviceProvider.GetServices<IPrimaryService>().ToArray();
		var baseServices = serviceProvider.GetServices<IAliasService>().ToArray();

		// Assert - Both collections have 2 instances
		Assert.Equal(2, primaryServices.Length);
		Assert.Equal(2, baseServices.Length);

		// Assert - Corresponding indices return the same instance
		Assert.Same(primaryServices[0], baseServices[0]);
		Assert.Same(primaryServices[1], baseServices[1]);

		// Assert - Correct types in registration order
		Assert.IsType<ServiceA>(primaryServices[0]);
		Assert.IsType<ServiceB>(primaryServices[1]);

		Assert.IsType<ServiceA>(baseServices[0]);
		Assert.IsType<ServiceB>(baseServices[1]);
	}

	/// <summary>
	/// Verifies that resolving both the primary interface and alias interface
	/// returns the same instance (same reference) when aliasing resolves through source.
	/// </summary>
	[Fact]
	public void AddAlias_WhenResolvingIndividually_ReturnsSameInstance()
	{
		// Arrange
		var services = new ServiceCollection();
		services.AddSingleton<ServiceA>();
		services.AddAlias<IPrimaryService, ServiceA>();
		services.AddAlias<IBaseService, ServiceA>();

		var serviceProvider = services.BuildServiceProvider();

		// Act
		var primaryService = serviceProvider.GetRequiredService<IPrimaryService>();
		var baseService = serviceProvider.GetRequiredService<IBaseService>();

		// Assert - Both aliases resolve through Service, returning same instance
		Assert.Same(primaryService, baseService);
	}

	/// <summary>
	/// Verifies that resolving IEnumerable of alias interface returns
	/// instances from all aliased sources through resolution.
	/// </summary>
	[Fact]
	public void AddAlias_WhenResolvingAsIEnumerable_ReturnsFromAllAliases()
	{
		// Arrange
		var services = new ServiceCollection();

		// Register two different implementation types
		services.AddSingleton<ServiceA>();
		services.AddAlias<IAliasService, ServiceA>();

		services.AddSingleton<ServiceB>();
		services.AddAlias<IAliasService, ServiceB>();

		var serviceProvider = services.BuildServiceProvider();

		// Act
		var aliasServices = serviceProvider.GetRequiredService<IEnumerable<IAliasService>>().ToArray();

		// Assert - Should have two entries (one for each alias)
		Assert.Equal(2, aliasServices.Length);
		Assert.NotNull(aliasServices[0]);
		Assert.NotNull(aliasServices[1]);
		Assert.NotSame(aliasServices[0], aliasServices[1]);
	}

	/// <summary>
	/// Verifies that AddAlias preserves the lifetime of the original registration.
	/// </summary>
	[Theory]
	[InlineData(ServiceLifetime.Transient)]
	[InlineData(ServiceLifetime.Scoped)]
	[InlineData(ServiceLifetime.Singleton)]
	public void AddAlias_PreservesOriginalLifetime(ServiceLifetime lifetime)
	{
		// Arrange
		var services = new ServiceCollection();

		switch (lifetime)
		{
			case ServiceLifetime.Transient:
				services.AddTransient<ServiceA>();
				break;
			case ServiceLifetime.Scoped:
				services.AddScoped<ServiceA>();
				break;
			case ServiceLifetime.Singleton:
				services.AddSingleton<ServiceA>();
				break;
		}

		services.AddAlias<IAliasService, ServiceA>();

		// Act
		var aliasDescriptor = services.Last(d => d.ServiceType == typeof(IAliasService));

		// Assert
		Assert.Equal(lifetime, aliasDescriptor.Lifetime);
	}

	/// <summary>
	/// Verifies that AddAlias throws when source service is not registered.
	/// </summary>
	[Fact]
	public void AddAlias_WhenSourceNotRegistered_ThrowsException()
	{
		// Arrange
		var services = new ServiceCollection();

		// Act & Assert
		var exception = Assert.Throws<InvalidOperationException>(
			() => services.AddAlias<IAliasService, ServiceA>());

		Assert.Contains("No registration found", exception.Message);
		Assert.Contains(nameof(ServiceA), exception.Message);
	}

	/// <summary>
	/// Verifies that for Singleton lifetime, the same instance is returned
	/// even across different service provider scopes.
	/// </summary>
	[Fact]
	public void AddAlias_WithSingleton_ReturnsSameInstanceAcrossScopes()
	{
		// Arrange
		var services = new ServiceCollection();
		services.AddSingleton<ServiceA>();
		services.AddAlias<IPrimaryService, ServiceA>();
		services.AddAlias<IAliasService, ServiceA>();

		var serviceProvider = services.BuildServiceProvider();

		// Act
		IPrimaryService primaryService1;
		IAliasService aliasService1;
		using (var scope1 = serviceProvider.CreateScope())
		{
			primaryService1 = scope1.ServiceProvider.GetRequiredService<IPrimaryService>();
			aliasService1 = scope1.ServiceProvider.GetRequiredService<IAliasService>();
		}

		IPrimaryService primaryService2;
		IAliasService aliasService2;
		using (var scope2 = serviceProvider.CreateScope())
		{
			primaryService2 = scope2.ServiceProvider.GetRequiredService<IPrimaryService>();
			aliasService2 = scope2.ServiceProvider.GetRequiredService<IAliasService>();
		}

		// Assert - all should be the same instance for Singleton
		Assert.Same(primaryService1, primaryService2);
		Assert.Same(aliasService1, aliasService2);
		Assert.Same(primaryService1, aliasService1);
	}

	/// <summary>
	/// Verifies that for Scoped lifetime, the same instance is returned within a scope
	/// but different instances across different scopes.
	/// </summary>
	[Fact]
	public void AddAlias_WithScoped_ReturnsSameInstanceWithinScope()
	{
		// Arrange
		var services = new ServiceCollection();
		services.AddScoped<ServiceA>();
		services.AddAlias<IPrimaryService, ServiceA>();
		services.AddAlias<IAliasService, ServiceA>();

		var serviceProvider = services.BuildServiceProvider();

		// Act & Assert - Within same scope
		using (var scope1 = serviceProvider.CreateScope())
		{
			var primaryService = scope1.ServiceProvider.GetRequiredService<IPrimaryService>();
			var aliasService = scope1.ServiceProvider.GetRequiredService<IAliasService>();

			Assert.Same(primaryService, aliasService);
		}

		// Act & Assert - Different scopes get different instances
		IPrimaryService instance1;
		using (var scope2 = serviceProvider.CreateScope())
		{
			instance1 = scope2.ServiceProvider.GetRequiredService<IPrimaryService>();
		}

		IPrimaryService instance2;
		using (var scope3 = serviceProvider.CreateScope())
		{
			instance2 = scope3.ServiceProvider.GetRequiredService<IPrimaryService>();
		}

		Assert.NotSame(instance1, instance2);
	}

	/// <summary>
	/// Verifies that for Transient lifetime, different instances are always returned.
	/// </summary>
	[Fact]
	public void AddAlias_WithTransient_ReturnsDifferentInstances()
	{
		// Arrange
		var services = new ServiceCollection();
		services.AddTransient<ServiceA>();
		services.AddAlias<IPrimaryService, ServiceA>();
		services.AddAlias<IAliasService, ServiceA>();

		var serviceProvider = services.BuildServiceProvider();

		// Act
		var primaryService1 = serviceProvider.GetRequiredService<IPrimaryService>();
		var primaryService2 = serviceProvider.GetRequiredService<IPrimaryService>();
		var aliasService1 = serviceProvider.GetRequiredService<IAliasService>();
		var aliasService2 = serviceProvider.GetRequiredService<IAliasService>();

		// Assert - All should be different instances for Transient
		Assert.NotSame(primaryService1, primaryService2);
		Assert.NotSame(aliasService1, aliasService2);
		Assert.NotSame(primaryService1, aliasService1);
	}
}
