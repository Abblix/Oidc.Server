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
using System.Linq;
using Abblix.DependencyInjection.UnitTests.Model;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.DependencyInjection.UnitTests;

/// <summary>
/// Tests for the AddKeyedAlias extension method to verify keyed service aliasing with proper instance resolution.
/// </summary>
public class AddKeyedAliasTests
{
	/// <summary>
	/// Verifies that resolving keyed aliases from different interfaces returns the same instance.
	/// </summary>
	[Fact]
	public void AddKeyedAlias_WhenResolvingWithSameKey_ReturnsSameInstance()
	{
		// Arrange
		var services = new ServiceCollection();
		const string key = "test-key";

		services.AddKeyedSingleton<ServiceA>(key);
		services.AddKeyedAlias<IPrimaryService, ServiceA>(key, key);
		services.AddKeyedAlias<IAliasService, ServiceA>(key, key);

		var serviceProvider = services.BuildServiceProvider();

		// Act
		var service = serviceProvider.GetRequiredKeyedService<ServiceA>(key);
		var primaryService = serviceProvider.GetRequiredKeyedService<IPrimaryService>(key);
		var aliasService = serviceProvider.GetRequiredKeyedService<IAliasService>(key);

		// Assert - All should be the same instance
		Assert.Same(service, primaryService);
		Assert.Same(service, aliasService);
		Assert.Same(primaryService, aliasService);
	}

	/// <summary>
	/// Verifies that aliasing from non-keyed to keyed service works correctly.
	/// </summary>
	[Fact]
	public void AddKeyedAlias_FromNonKeyedToKeyed_ReturnsCorrectInstance()
	{
		// Arrange
		var services = new ServiceCollection();
		const string key = "my-key";

		services.AddSingleton<ServiceA>();
		services.AddKeyedAlias<IPrimaryService, ServiceA>(key, sourceKey: null);

		var serviceProvider = services.BuildServiceProvider();

		// Act
		var service = serviceProvider.GetRequiredService<ServiceA>();
		var primaryService = serviceProvider.GetRequiredKeyedService<IPrimaryService>(key);

		// Assert - Should be the same instance
		Assert.Same(service, primaryService);
	}

	/// <summary>
	/// Verifies that different keys result in different service instances for Transient lifetime.
	/// </summary>
	[Fact]
	public void AddKeyedAlias_WithTransientLifetime_ReturnsDifferentInstances()
	{
		// Arrange
		var services = new ServiceCollection();
		const string key1 = "key1";
		const string key2 = "key2";

		services.AddKeyedTransient<ServiceA>(key1);
		services.AddKeyedAlias<IPrimaryService, ServiceA>(key1, key1);

		services.AddKeyedTransient<ServiceA>(key2);
		services.AddKeyedAlias<IPrimaryService, ServiceA>(key2, key2);

		var serviceProvider = services.BuildServiceProvider();

		// Act
		var service1 = serviceProvider.GetRequiredKeyedService<IPrimaryService>(key1);
		var service2 = serviceProvider.GetRequiredKeyedService<IPrimaryService>(key2);

		// Assert - Different keys should return different instances
		Assert.NotSame(service1, service2);
	}

	/// <summary>
	/// Verifies that AddKeyedAlias preserves the lifetime of the original registration.
	/// </summary>
	[Theory]
	[InlineData(ServiceLifetime.Transient)]
	[InlineData(ServiceLifetime.Scoped)]
	[InlineData(ServiceLifetime.Singleton)]
	public void AddKeyedAlias_PreservesOriginalLifetime(ServiceLifetime lifetime)
	{
		// Arrange
		var services = new ServiceCollection();
		const string key = "test-key";

		switch (lifetime)
		{
			case ServiceLifetime.Transient:
				services.AddKeyedTransient<ServiceA>(key);
				break;
			case ServiceLifetime.Scoped:
				services.AddKeyedScoped<ServiceA>(key);
				break;
			case ServiceLifetime.Singleton:
				services.AddKeyedSingleton<ServiceA>(key);
				break;
		}

		services.AddKeyedAlias<IAliasService, ServiceA>(key, key);

		// Act
		var aliasDescriptor = services.Last(d => d.ServiceType == typeof(IAliasService) && Equals(d.ServiceKey, key));

		// Assert
		Assert.Equal(lifetime, aliasDescriptor.Lifetime);
	}

	/// <summary>
	/// Verifies that AddKeyedAlias throws when source service is not registered.
	/// </summary>
	[Fact]
	public void AddKeyedAlias_WhenSourceNotRegistered_ThrowsException()
	{
		// Arrange
		var services = new ServiceCollection();
		const string key = "missing-key";

		// Act & Assert
		var exception = Assert.Throws<InvalidOperationException>(
			() => services.AddKeyedAlias<IAliasService, ServiceA>(key, key));

		Assert.Contains("No registration found", exception.Message);
		Assert.Contains(nameof(ServiceA), exception.Message);
	}

	/// <summary>
	/// Verifies that for Scoped lifetime, the same instance is returned within a scope
	/// but different instances across different scopes.
	/// </summary>
	[Fact]
	public void AddKeyedAlias_WithScoped_ReturnsSameInstanceWithinScope()
	{
		// Arrange
		var services = new ServiceCollection();
		const string key = "scoped-key";

		services.AddKeyedScoped<ServiceA>(key);
		services.AddKeyedAlias<IPrimaryService, ServiceA>(key, key);
		services.AddKeyedAlias<IAliasService, ServiceA>(key, key);

		var serviceProvider = services.BuildServiceProvider();

		// Act & Assert - Within same scope
		using (var scope1 = serviceProvider.CreateScope())
		{
			var primaryService = scope1.ServiceProvider.GetRequiredKeyedService<IPrimaryService>(key);
			var aliasService = scope1.ServiceProvider.GetRequiredKeyedService<IAliasService>(key);

			Assert.Same(primaryService, aliasService);
		}

		// Act & Assert - Different scopes get different instances
		IPrimaryService instance1;
		using (var scope2 = serviceProvider.CreateScope())
		{
			instance1 = scope2.ServiceProvider.GetRequiredKeyedService<IPrimaryService>(key);
		}

		IPrimaryService instance2;
		using (var scope3 = serviceProvider.CreateScope())
		{
			instance2 = scope3.ServiceProvider.GetRequiredKeyedService<IPrimaryService>(key);
		}

		Assert.NotSame(instance1, instance2);
	}

	/// <summary>
	/// Verifies that multiple keyed services can be aliased and resolved as a collection.
	/// </summary>
	[Fact]
	public void AddKeyedAlias_MultipleKeysWithSameType_ReturnsAllInstances()
	{
		// Arrange
		var services = new ServiceCollection();
		const string key1 = "primary";
		const string key2 = "secondary";

		services.AddKeyedSingleton<ServiceA>(key1);
		services.AddKeyedAlias<IPrimaryService, ServiceA>(key1, key1);

		services.AddKeyedSingleton<ServiceB>(key2);
		services.AddKeyedAlias<IPrimaryService, ServiceB>(key2, key2);

		var serviceProvider = services.BuildServiceProvider();

		// Act
		var service1 = serviceProvider.GetRequiredKeyedService<IPrimaryService>(key1);
		var service2 = serviceProvider.GetRequiredKeyedService<IPrimaryService>(key2);

		// Assert - Different keys return different types
		Assert.IsType<ServiceA>(service1);
		Assert.IsType<ServiceB>(service2);
		Assert.NotSame(service1, service2);
	}
}
