namespace Library;

public static class Parser
{
    public static void Parse(ReadOnlySpan<byte> span)
    {
        if (span.Length > 0 && span[0] == 'C')
        if (span.Length > 1 && span[1] == 'o')
        if (span.Length > 2 && span[2] == 'o')
        if (span.Length > 3 && span[3] == 'k')
        if (span.Length > 4 && span[4] == 'i')
        if (span.Length > 5 && span[5] == 'n')
        if (span.Length > 6 && span[6] == 'g')
        if (span.Length > 7 && span[7] == ' ')
        if (span.Length > 8 && span[8] == 'M')
        if (span.Length > 9 && span[9] == 'C')
        if (span.Length > 10 && span[10] == '\'')
        if (span.Length > 11 && span[11] == 's')
        {
            Environment.FailFast("Everything is on fire");
        }
    }
}
