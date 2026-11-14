// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Mvc.Attributes;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Xunit;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Attributes;

/// <summary>
/// What MVC reads off the attribute when it binds a parameter carrying it.
/// </summary>
public class FromQueryOrFormAttributeTests
{
    private static readonly BindingInfo Binding = BindingInfo.GetBindingInfo([new FromQueryOrFormAttribute()])!;

    /// <summary>
    /// The model's parameters are read under their own names, never under a prefix naming the action parameter.
    /// </summary>
    [Fact]
    public void ParametersAreReadWithoutAPrefix() => Assert.Equal(string.Empty, Binding.BinderModelName);

    [Fact]
    public void QueryAndFormAreBothRead()
    {
        Assert.True(Binding.BindingSource!.CanAcceptDataFrom(BindingSource.Query));
        Assert.True(Binding.BindingSource.CanAcceptDataFrom(BindingSource.Form));
        Assert.False(Binding.BindingSource.CanAcceptDataFrom(BindingSource.Header));
    }
}
