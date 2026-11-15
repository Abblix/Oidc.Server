// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// A request body holding one valid JSON object whose single string member makes it <paramref name="length"/> bytes
/// long, produced as it is read and counting how much of it was taken, so a test tells a body the server read from
/// one it left unread whatever status it answered. Valid throughout, so a JSON reader taking it never stops early.
/// </summary>
/// <param name="member">The name of the string member.</param>
/// <param name="length">The length of the whole document in bytes.</param>
public sealed class MeteredJsonStream(string member, long length) : Stream
{
    private readonly byte[] _prefix = Encoding.UTF8.GetBytes($"{{\"{member}\": \"");
    private static readonly byte[] Suffix = Encoding.UTF8.GetBytes("\"}");

    /// <summary>How many bytes of the document were read.</summary>
    public long Produced { get; private set; }

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count)
    {
        var written = 0;
        while (written < count && Produced < length)
        {
            buffer[offset + written] = ByteAt(Produced);
            written++;
            Produced++;
        }

        return written;
    }

    private byte ByteAt(long position)
    {
        if (position < _prefix.Length)
            return _prefix[position];

        var fromEnd = length - position;
        if (fromEnd <= Suffix.Length)
            return Suffix[Suffix.Length - fromEnd];

        return (byte)'a';
    }

    /// <inheritdoc />
    public override bool CanRead => true;

    /// <inheritdoc />
    public override bool CanSeek => false;

    /// <inheritdoc />
    public override bool CanWrite => false;

    /// <inheritdoc />
    public override long Length => throw new NotSupportedException();

    /// <inheritdoc />
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    /// <inheritdoc />
    public override void Flush()
    {
    }

    /// <inheritdoc />
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    /// <inheritdoc />
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
