
include("../src/Steganography.jl")
using Base.Test

using Steganography

@testset "steganography" begin
    @testset "$S in $T" for S in [UInt8], T in [Float32, Float64]
        n = 1024
        A = rand(T, n)
        U = rand(S, n)
        U7 = U .>> 1
        for j in 1:n
            r = setlast8(A[j], U[j])
            s = setlastbits(A[j], U[j], UInt8(8))
            u = setlast7(A[j], U7[j])
            v = setlastbits(A[j], U7[j], UInt8(7))
            @test r == s
            @test u == v
            @test getlast8(u) == getlastbits(u, UInt8(8))
            @test getlast7(u) == getlastbits(u, UInt8(7))
            @test U7[j] == getlast7(u)
            @test U[j] == getlast8(r)
        end
        A = rand(T, n + 2)
        V = extract(embed(A, U7))
        @test U == V
    end
end
