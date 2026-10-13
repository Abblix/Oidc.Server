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
/// A registration body whose read fails gets the status the framework's own body binding gives it. These failures
/// come from the server and the connection, which the in-memory host of the end-to-end suites never produces: only
/// Kestrel enforces the size bound, and only a real client breaks a read off. So the read is driven here with a body
/// that fails the way each of them does.
/// </summary>
public class ClientMetadataBodyTests
{
    public static TheoryData<Exception, int> FailedReads() => new()
    {
        { new BadHttpRequestException("Request body too large.", StatusCodes.Status413PayloadTooLarge),
            StatusCodes.Status413PayloadTooLarge },
        { new IOException("The client reset the connection."), StatusCodes.Status400BadRequest },
        { new OperationCanceledException(), StatusCodes.Status400BadRequest },
    };

    [Theory]
    [MemberData(nameof(FailedReads))]
    public async Task AFailedReadGetsTheStatusTheFrameworkGivesIt(Exception failure, int expected)
    {
        var context = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection().AddOptions().BuildServiceProvider(),
        };
        context.Request.ContentType = MediaTypeNames.Application.Json;
        context.Request.Body = new RefusingStream(failure);

        var body = await ClientMetadataBody.BindAsync(context);

        Assert.Null(body.Request);
        var status = Assert.IsAssignableFrom<IStatusCodeHttpResult>(body.Refusal);
        Assert.Equal(expected, status.StatusCode);
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
