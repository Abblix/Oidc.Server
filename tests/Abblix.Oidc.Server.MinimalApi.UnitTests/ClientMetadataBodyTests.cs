// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Mime;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Abblix.Oidc.Server.MinimalApi.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using JsonOptions = Microsoft.AspNetCore.Http.Json.JsonOptions;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.MinimalApi.UnitTests;

/// <summary>
/// A registration body whose read fails for a reason outside the document: past the size bound it keeps the status
/// the server gave it, and broken off or cancelled it gets the bare 400 the framework's own body binding gives it.
/// These failures come from the server and the connection, which the in-memory host of the end-to-end suites never
/// produces: only Kestrel enforces the size bound, and only a real client breaks a read off. So the read is driven
/// here with a body that fails the way each of them does.
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

    /// <summary>
    /// A fault in the host's own JSON configuration stays a server fault: it is not taken for a body in a character
    /// set nobody can decode, which the reader reports with the same exception.
    /// </summary>
    [Fact]
    public async Task AFaultInTheHostsConvertersIsNotAnsweredAsAnUnsupportedMediaType()
    {
        var services = new ServiceCollection().AddOptions();
        services.Configure<JsonOptions>(options => options.SerializerOptions.Converters.Add(new FaultyUriConverter()));

        var context = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
        context.Request.ContentType = MediaTypeNames.Application.Json;
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(
            $$"""{"{{RegistrationMembers.RedirectUris}}": ["https://client.example/cb"]}"""));

        await Assert.ThrowsAsync<InvalidOperationException>(() => ClientMetadataBody.BindAsync(context).AsTask());
    }

    /// <summary>A host converter that cannot read what it was registered for.</summary>
    private sealed class FaultyUriConverter : JsonConverter<Uri>
    {
        public override Uri Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            => throw new InvalidOperationException("The host's converter is misconfigured.");

        public override void Write(Utf8JsonWriter writer, Uri value, JsonSerializerOptions options)
            => throw new NotSupportedException();
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
