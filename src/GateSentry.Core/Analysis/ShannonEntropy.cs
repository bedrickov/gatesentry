namespace GateSentry.Core.Analysis;

public static class ShannonEntropy
{
    /// <summary>
    /// Calculates Shannon Entropy (in bits) for the given character sequence.
    /// Higher values (typically > 3.5 - 4.5) indicate high randomness (e.g. hashed secrets, private keys, API tokens).
    /// </summary>
    public static double Calculate(ReadOnlySpan<char> text)
    {
        if (text.IsEmpty)
        {
            return 0.0;
        }

        // Count frequencies using stackalloc for ASCII or dictionary for full unicode
        Span<int> freq = stackalloc int[256];
        int len = 0;

        foreach (char c in text)
        {
            if (char.IsWhiteSpace(c))
                continue;

            len++;
            if (c < 256)
            {
                freq[c]++;
            }
        }

        if (len == 0)
        {
            return 0.0;
        }

        double entropy = 0.0;
        for (int i = 0; i < 256; i++)
        {
            int count = freq[i];
            if (count > 0)
            {
                double probability = (double)count / len;
                entropy -= probability * Math.Log2(probability);
            }
        }

        return entropy;
    }
}
