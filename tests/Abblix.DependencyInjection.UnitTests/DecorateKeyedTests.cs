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
/// Tests for the DecorateKeyed extension method.
/// </summary>
public class DecorateKeyedTests
{
	private const string TestKey = "TestKey";

	/// <summary>
	/// Verifies that DecorateKeyed decorates an existing keyed service.
	/// </summary>
	[Fact]
	public void DecorateKeyed_WhenKeyedServiceExists_DecoratesIt()
	{
		// Arrange
		var services = new ServiceCollection();
		services.AddKeyedScoped<IBaseService, ServiceA>(TestKey);

		// Act
		services.DecorateKeyed<IBaseService, ServiceDecorator>(TestKey);
		var serviceProvider = services.BuildServiceProvider();

		// Assert
		var service = serviceProvider.GetRequiredKeyedService<IBaseService>(TestKey);
		Assert.IsType<ServiceDecorator>(service);
		var decorator = (ServiceDecorator)service;
		Assert.IsType<ServiceA>(decorator.Inner);
		Assert.StartsWith("Decorated:ServiceA", service.GetValue());
	}

	/// <summary>
	/// Verifies that DecorateKeyed falls back to decorating the non-keyed service
	/// when no keyed service exists with the specified key.
	/// </summary>
	[Fact]
	public void DecorateKeyed_WhenKeyedServiceNotFound_FallsBackToNonKeyed()
	{
		// Arrange
		var services = new ServiceCollection();
		services.AddScoped<IBaseService, ServiceA>();

		// Act
		services.DecorateKeyed<IBaseService, ServiceDecorator>(TestKey);
		var serviceProvider = services.BuildServiceProvider();

		// Assert - keyed service resolves to decorated version
		var keyedService = serviceProvider.GetRequiredKeyedService<IBaseService>(TestKey);
		Assert.IsType<ServiceDecorator>(keyedService);
		var decorator = (ServiceDecorator)keyedService;
		Assert.IsType<ServiceA>(decorator.Inner);

		// Assert - non-keyed service remains unchanged
		var nonKeyedService = serviceProvider.GetRequiredService<IBaseService>();
		Assert.IsType<ServiceA>(nonKeyedService);
	}

	/// <summary>
	/// Verifies that DecorateKeyed preserves the original service lifetime.
	/// </summary>
	[Theory]
	[InlineData(ServiceLifetime.Transient)]
	[InlineData(ServiceLifetime.Scoped)]
	[InlineData(ServiceLifetime.Singleton)]
	public void DecorateKeyed_PreservesOriginalLifetime(ServiceLifetime lifetime)
	{
		// Arrange
		var services = new ServiceCollection();

		switch (lifetime)
		{
			case ServiceLifetime.Transient:
				services.AddTransient<IBaseService, ServiceA>();
				break;
			case ServiceLifetime.Scoped:
				services.AddScoped<IBaseService, ServiceA>();
				break;
			case ServiceLifetime.Singleton:
				services.AddSingleton<IBaseService, ServiceA>();
				break;
		}

		// Act
		services.DecorateKeyed<IBaseService, ServiceDecorator>(TestKey);

		// Assert
		var descriptor = services.Last(d =>
			d.ServiceType == typeof(IBaseService) &&
			Equals(d.ServiceKey, TestKey));
		Assert.Equal(lifetime, descriptor.Lifetime);
	}

	/// <summary>
	/// Verifies that DecorateKeyed throws an exception when no matching service is found.
	/// </summary>
	[Fact]
	public void DecorateKeyed_WhenNoServiceFound_ThrowsException()
	{
		// Arrange
		var services = new ServiceCollection();

		// Act & Assert
		var exception = Assert.Throws<InvalidOperationException>(
			() => services.DecorateKeyed<IBaseService, ServiceDecorator>(TestKey));
		Assert.Contains("No service of type", exception.Message);
		Assert.Contains(nameof(IBaseService), exception.Message);
	}

	/// <summary>
	/// Verifies that DecorateKeyed prefers keyed service over non-keyed when both exist.
	/// </summary>
	[Fact]
	public void DecorateKeyed_WhenBothKeyedAndNonKeyedExist_PrefersKeyed()
	{
		// Arrange
		var services = new ServiceCollection();
		services.AddScoped<IBaseService, ServiceA>();
		services.AddKeyedScoped<IBaseService, ServiceB>(TestKey);

		// Act
		services.DecorateKeyed<IBaseService, ServiceDecorator>(TestKey);
		var serviceProvider = services.BuildServiceProvider();

		// Assert - keyed service decorates ServiceB (the keyed one)
		var keyedService = serviceProvider.GetRequiredKeyedService<IBaseService>(TestKey);
		Assert.IsType<ServiceDecorator>(keyedService);
		var decorator = (ServiceDecorator)keyedService;
		Assert.IsType<ServiceB>(decorator.Inner);

		// Assert - non-keyed service remains unchanged
		var nonKeyedService = serviceProvider.GetRequiredService<IBaseService>();
		Assert.IsType<ServiceA>(nonKeyedService);
	}

	/// <summary>
	/// Verifies that the decorated keyed service wraps the inner service correctly
	/// and passes calls through.
	/// </summary>
	[Fact]
	public void DecorateKeyed_DecoratorWrapsInnerService_PassesCallsThrough()
	{
		// Arrange
		var services = new ServiceCollection();
		services.AddScoped<IBaseService, ServiceA>();
		services.DecorateKeyed<IBaseService, ServiceDecorator>(TestKey);
		var serviceProvider = services.BuildServiceProvider();

		// Act
		var service = serviceProvider.GetRequiredKeyedService<IBaseService>(TestKey);

		// Assert
		Assert.StartsWith("Decorated:ServiceA", service.GetValue());
	}

	/// <summary>
	/// Verifies that Scoped lifetime works correctly - same instance within scope,
	/// different instances across scopes.
	/// </summary>
	[Fact]
	public void DecorateKeyed_WithScopedLifetime_SameInstanceWithinScope()
	{
		// Arrange
		var services = new ServiceCollection();
		services.AddScoped<IBaseService, ServiceA>();
		services.DecorateKeyed<IBaseService, ServiceDecorator>(TestKey);
		var serviceProvider = services.BuildServiceProvider();

		// Act & Assert - Same instance within scope
		using var scope = serviceProvider.CreateScope();
		var service1 = scope.ServiceProvider.GetRequiredKeyedService<IBaseService>(TestKey);
		var service2 = scope.ServiceProvider.GetRequiredKeyedService<IBaseService>(TestKey);
		Assert.Same(service1, service2);
	}
}
