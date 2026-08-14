using System.Net;

namespace Abblix.Jwt.Azure.UnitTests;

/// <summary>
/// An origin that fails a set number of times before answering, so a retry is visible as a request count rather
/// than inferred from the presence of a handler.
/// </summary>
/// <param name="failuresBeforeSuccess">How many attempts are refused before one succeeds.</param>
public sealed class FlakyOriginHandler(int failuresBeforeSuccess) : HttpMessageHandler
{
    /// <summary>How many attempts reached the origin.</summary>
    public int Requests { get; private set; }

    /// <inheritdoc />
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        Requests++;

        // 503 is what the standard pipeline treats as worth retrying; a 400 would prove nothing, since the
        // pipeline is right not to repeat it.
        return Task.FromResult(new HttpResponseMessage(
            Requests <= failuresBeforeSuccess ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK));
    }
}
