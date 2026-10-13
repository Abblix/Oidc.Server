// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Mime;
using Abblix.Oidc.Server.MinimalApi.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.MinimalApi.UnitTests;

/// <summary>
/// A registration body the server refuses while it is read keeps the status the server gave it. Only Kestrel
/// enforces the size bound, so the in-memory host of the end-to-end suites never reaches this, and the read is
/// driven here with a body that fails the way Kestrel's does past the bound.
/// </summary>
public class ClientMetadataBodyTests
{
    [Fact]
    public async Task ABodyPastTheSizeBoundKeepsTheStatusTheServerGaveIt()
    {
        var context = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection().AddOptions().BuildServiceProvider(),
        };
        context.Request.ContentType = MediaTypeNames.Application.Json;
        context.Request.Body = new RefusingStream(new BadHttpRequestException(
            "Request body too large.", StatusCodes.Status413PayloadTooLarge));

        var body = await ClientMetadataBody.BindAsync(context);

        Assert.Null(body.Request);
        var status = Assert.IsAssignableFrom<IStatusCodeHttpResult>(body.Refusal);
        Assert.Equal(StatusCodes.Status413PayloadTooLarge, status.StatusCode);
    }

    /// <summary>A request body whose first read fails as the server fails it.</summary>
    private sealed class RefusingStream(Exception failure) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => throw failure;
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => throw failure;
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => throw failure;
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
