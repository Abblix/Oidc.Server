// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Xunit;

namespace Abblix.Oidc.Server.MinimalApi.UnitTests;

/// <summary>
/// A form the host cannot read comes back as no form, for the model to record and the filter to refuse, for the same
/// two failures the MVC host refuses: one past the form limits, and one whose body fails to arrive. The second is
/// driven here rather than end to end, because the in-memory server hands a failing request body back to the client
/// that sent it instead of to the endpoint.
/// </summary>
public class FormValuesReadFormTests
{
    private const string FormContentType = "application/x-www-form-urlencoded";

    [Fact]
    public async Task FormIsRead()
    {
        var form = await FormValues.ReadFormAsync(RequestWith(new MemoryStream(Encoding.ASCII.GetBytes("a=1&b=2"))), TestContext.Current.CancellationToken);

        Assert.NotNull(form);
        Assert.Equal("1", form["a"].ToString());
    }

    [Fact]
    public async Task FormPastTheLimitsIsNoForm()
    {
        var request = RequestWith(new MemoryStream(Encoding.ASCII.GetBytes("a=1&b=2")));
        request.HttpContext.Features.Set<IFormFeature>(new FormFeature(request, new() { ValueCountLimit = 1 }));

        Assert.Null(await FormValues.ReadFormAsync(request, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task FormBodyThatBreaksOffIsNoForm()
        => Assert.Null(await FormValues.ReadFormAsync(RequestWith(new BreakingStream()), TestContext.Current.CancellationToken));

    [Fact]
    public async Task RequestWithoutAFormIsNoForm()
    {
        var request = new DefaultHttpContext().Request;

        Assert.Null(await FormValues.ReadFormAsync(request, TestContext.Current.CancellationToken));
    }

    private static HttpRequest RequestWith(Stream body)
    {
        var request = new DefaultHttpContext().Request;
        request.ContentType = FormContentType;
        request.Body = body;
        return request;
    }

    /// <summary>
    /// A request body that fails while it is read, as a connection dropped mid-body does.
    /// </summary>
    private sealed class BreakingStream : MemoryStream
    {
        public override int Read(byte[] buffer, int offset, int count)
            => throw new IOException("The connection was closed while the body was read.");

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => throw new IOException("The connection was closed while the body was read.");
    }
}
