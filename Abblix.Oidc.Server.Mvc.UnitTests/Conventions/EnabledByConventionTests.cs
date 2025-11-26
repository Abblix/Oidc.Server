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

using System.Reflection;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Mvc.Conventions;
using Abblix.Oidc.Server.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Conventions;

/// <summary>
/// Unit tests for <see cref="EnabledByConvention"/>.
/// </summary>
public class EnabledByConventionTests
{
    [Fact]
    public void Apply_WhenEndpointEnabled_ControllerRemains()
    {
        // Arrange
        var options = new OidcOptions
        {
            EnabledEndpoints = OidcEndpoints.RegisterClient
        };
        var convention = new EnabledByConvention(Options.Create(options));
        var application = CreateApplicationModelWithController(OidcEndpoints.RegisterClient);

        // Act
        convention.Apply(application);

        // Assert
        Assert.Single(application.Controllers);
    }

    [Fact]
    public void Apply_WhenEndpointDisabled_ControllerRemoved()
    {
        // Arrange
        var options = new OidcOptions
        {
            EnabledEndpoints = OidcEndpoints.All & ~OidcEndpoints.RegisterClient
        };
        var convention = new EnabledByConvention(Options.Create(options));
        var application = CreateApplicationModelWithController(OidcEndpoints.RegisterClient);

        // Act
        convention.Apply(application);

        // Assert
        Assert.Empty(application.Controllers);
    }

    [Fact]
    public void Apply_WhenControllerHasNoAttribute_ControllerRemains()
    {
        // Arrange
        var options = new OidcOptions
        {
            EnabledEndpoints = OidcEndpoints.All
        };
        var convention = new EnabledByConvention(Options.Create(options));
        var application = CreateApplicationModelWithController(null);

        // Act
        convention.Apply(application);

        // Assert
        Assert.Single(application.Controllers);
    }

    [Fact]
    public void Apply_WithMultipleControllers_RemovesOnlyDisabled()
    {
        // Arrange
        var options = new OidcOptions
        {
            EnabledEndpoints = OidcEndpoints.All & ~OidcEndpoints.RegisterClient
        };
        var convention = new EnabledByConvention(Options.Create(options));
        var application = new ApplicationModel();

        // Add controller with Register endpoint (should be removed)
        application.Controllers.Add(CreateController(OidcEndpoints.RegisterClient));

        // Add controller with Token endpoint (should remain)
        application.Controllers.Add(CreateController(OidcEndpoints.Token));

        // Add controller without attribute (should remain)
        application.Controllers.Add(CreateController(null));

        // Act
        convention.Apply(application);

        // Assert
        Assert.Equal(2, application.Controllers.Count);
    }

    [Fact]
    public void Apply_WhenActionHasDisabledEndpoint_ActionRemoved()
    {
        // Arrange
        var options = new OidcOptions
        {
            EnabledEndpoints = OidcEndpoints.All & ~OidcEndpoints.RegisterClient
        };
        var convention = new EnabledByConvention(Options.Create(options));
        var application = new ApplicationModel();

        var controller = CreateController(null);
        controller.Actions.Add(CreateAction(OidcEndpoints.RegisterClient, "RegisterAction"));
        controller.Actions.Add(CreateAction(null, "OtherAction"));
        application.Controllers.Add(controller);

        // Act
        convention.Apply(application);

        // Assert
        Assert.Single(application.Controllers);
        var remainingController = application.Controllers.First();
        Assert.Single(remainingController.Actions);
        Assert.Equal("OtherAction", remainingController.Actions.First().ActionName);
    }

    [Fact]
    public void Apply_WhenActionHasEnabledEndpoint_ActionRemains()
    {
        // Arrange
        var options = new OidcOptions
        {
            EnabledEndpoints = OidcEndpoints.RegisterClient
        };
        var convention = new EnabledByConvention(Options.Create(options));
        var application = new ApplicationModel();

        var controller = CreateController(null);
        controller.Actions.Add(CreateAction(OidcEndpoints.RegisterClient, "RegisterAction"));
        controller.Actions.Add(CreateAction(null, "OtherAction"));
        application.Controllers.Add(controller);

        // Act
        convention.Apply(application);

        // Assert
        Assert.Single(application.Controllers);
        var remainingController = application.Controllers.First();
        Assert.Equal(2, remainingController.Actions.Count);
    }

    [Fact]
    public void Apply_ControllerDisabled_ActionsNotChecked()
    {
        // Arrange
        var options = new OidcOptions
        {
            EnabledEndpoints = OidcEndpoints.All & ~OidcEndpoints.RegisterClient
        };
        var convention = new EnabledByConvention(Options.Create(options));
        var application = new ApplicationModel();

        var controller = CreateController(OidcEndpoints.RegisterClient);
        controller.Actions.Add(CreateAction(OidcEndpoints.Token, "TokenAction"));
        application.Controllers.Add(controller);

        // Act
        convention.Apply(application);

        // Assert - entire controller should be removed, actions not checked
        Assert.Empty(application.Controllers);
    }

    private static ApplicationModel CreateApplicationModelWithController(OidcEndpoints? endpoint)
    {
        var application = new ApplicationModel();
        application.Controllers.Add(CreateController(endpoint));
        return application;
    }

    private static ControllerModel CreateController(OidcEndpoints? endpoint)
    {
        var attributes = new List<object>();
        if (endpoint.HasValue)
        {
            attributes.Add(new EnabledByAttribute(endpoint.Value));
        }

        var controller = new ControllerModel(
            typeof(object).GetTypeInfo(),
            attributes);

        return controller;
    }

    private static ActionModel CreateAction(OidcEndpoints? endpoint, string actionName)
    {
        var attributes = new List<object>();
        if (endpoint.HasValue)
        {
            attributes.Add(new EnabledByAttribute(endpoint.Value));
        }

        var action = new ActionModel(
            typeof(object).GetMethod("ToString")!,
            attributes)
        {
            ActionName = actionName
        };

        return action;
    }
}
