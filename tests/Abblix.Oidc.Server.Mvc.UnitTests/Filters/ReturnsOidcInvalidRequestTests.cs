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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Controllers;
using Abblix.Oidc.Server.Mvc.Filters;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Routing;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Filters;

/// <summary>
/// Covers the OAuth invalid_request rendering of a failed model-validation pass, the ordering that lets it
/// pre-empt the <c>[ApiController]</c> automatic 400, and the requirement that every OIDC controller carries
/// the attribute (placement is what scopes the behaviour to this library's endpoints).
/// </summary>
public class ReturnsOidcInvalidRequestTests
{
    [Fact]
    public void OnActionExecuting_InvalidModelState_ShortCircuitsWithOAuthError()
    {
        var context = BuildContext(modelStateValid: false);

        new ReturnsOidcInvalidRequestAttribute().OnActionExecuting(context);

        var badRequest = Assert.IsType<BadRequestObjectResult>(context.Result);
        var body = Assert.IsType<ErrorResponse>(badRequest.Value);
        Assert.Equal(ErrorCodes.InvalidRequest, body.Error);
        Assert.Contains("bogus", body.ErrorDescription);
    }

    [Fact]
    public void OnActionExecuting_ValidModelState_DoesNotShortCircuit()
    {
        var context = BuildContext(modelStateValid: true);

        new ReturnsOidcInvalidRequestAttribute().OnActionExecuting(context);

        Assert.Null(context.Result);
    }

    [Fact]
    public void Order_SortsBeforeApiControllerModelStateValidation()
    {
        // The framework's ModelStateInvalidFilter (the [ApiController] auto-400) runs at -2000; this filter
        // must sort before it to pre-empt the automatic ProblemDetails response.
        Assert.True(new ReturnsOidcInvalidRequestAttribute().Order < -2000);
    }

    [Fact]
    public void Attribute_IsAppliedToEveryOidcController()
    {
        // Placement is the scoping mechanism, so a new controller without the attribute would silently fall
        // back to ProblemDetails. Guard every controller in the adapter assembly against that omission.
        var controllers = typeof(TokenController).Assembly.GetTypes()
            .Where(type => typeof(ControllerBase).IsAssignableFrom(type) && !type.IsAbstract)
            .ToArray();

        Assert.NotEmpty(controllers);
        foreach (var controller in controllers)
            Assert.True(
                controller.GetCustomAttribute<ReturnsOidcInvalidRequestAttribute>(inherit: true) is not null,
                $"{controller.Name} is missing [ReturnsOidcInvalidRequest]");
    }

    private static ActionExecutingContext BuildContext(bool modelStateValid)
    {
        var modelState = new ModelStateDictionary();
        if (!modelStateValid)
            modelState.AddModelError("response_mode", "The value 'bogus' is invalid");

        var actionContext = new ActionContext(
            new DefaultHttpContext(),
            new RouteData(),
            new ControllerActionDescriptor(),
            modelState);

        return new ActionExecutingContext(
            actionContext,
            new List<IFilterMetadata>(),
            new Dictionary<string, object?>(),
            controller: new object());
    }
}
