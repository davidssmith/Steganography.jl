
include("../src/Steganography.jl")
using Base.Test

@testset "steganography" begin
    @testset "$S in $T" for S in [UInt8], T in [Float32, Float64]
        n = 1024
        R = rand(T, n)
        U = rand(S, n)
        for j in 1:n
            r = setlast8(R[j], U[j])
            s = setlastbits(R[j], U[j], UInt8(8))
            u = setlast7(R[j], U[j])
            v = setlastbits(R[j], U[j], UInt8(7))
            @test r == s
            @test u == v
            @test getlast8(u) == getlastbits(u, UInt8(8))
            @test getlast7(u) == getlastbits(u, UInt8(7))
        end
    end
end
