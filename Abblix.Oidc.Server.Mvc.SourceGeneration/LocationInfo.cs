using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;

namespace Abblix.Oidc.Server.Mvc.SourceGeneration;

/// <summary>
/// A source location captured as equatable primitives, restorable to a <see cref="Location"/>
/// when the diagnostic is finally reported.
/// </summary>
internal sealed record LocationInfo(
    string FilePath,
    int SpanStart,
    int SpanLength,
    int StartLine,
    int StartCharacter,
    int EndLine,
    int EndCharacter)
{
    public static LocationInfo From(Location location)
    {
        var lineSpan = location.GetLineSpan();
        return new LocationInfo(
            lineSpan.Path,
            location.SourceSpan.Start,
            location.SourceSpan.Length,
            lineSpan.StartLinePosition.Line,
            lineSpan.StartLinePosition.Character,
            lineSpan.EndLinePosition.Line,
            lineSpan.EndLinePosition.Character);
    }

    public Location ToLocation()
        => Location.Create(
            FilePath,
            new TextSpan(SpanStart, SpanLength),
            new LinePositionSpan(
                new LinePosition(StartLine, StartCharacter),
                new LinePosition(EndLine, EndCharacter)));
}