using SharpFuzz;

namespace Library.Fuzz;

public class Program
{
    public static void Main()
    {
        Fuzzer.LibFuzzer.Run(span =>
        {
            Parser.Parse(span);
        });
    }
}
