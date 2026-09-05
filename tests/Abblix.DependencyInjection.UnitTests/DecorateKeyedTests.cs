// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
