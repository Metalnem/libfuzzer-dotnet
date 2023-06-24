using System;
using SharpFuzz;

namespace Library.Fuzz;

public class Program
{
    public static void Main(string[] args)
    {
        Fuzzer.LibFuzzer.Run(span =>
        {
            Parser.Parse(span);
        });
    }
}
