
include("../src/Steganography.jl")
using Base.Test

using Steganography

@testset "steganography" begin
    U = read("reliance.txt")
    #println(join(Char.(U)))
    n = length(U)
    @testset "$S in $T" for S in [UInt8], T in [Int32, Int64, UInt32, UInt64, Float32, Float64]
        A = rand(T, n)
        for j in 1:n
            r = setlast8(A[j], U[j])
            s = setlastbits(A[j], U[j], UInt8(8))
            u = setlast7(A[j], U[j])
            v = setlastbits(A[j], U[j], UInt8(7))
            @test r == s
            @test u == v
            @test getlast8(u) == getlastbits(u, UInt8(8))
            @test getlast7(u) == getlastbits(u, UInt8(7))
            @test U[j] == getlast7(u)
            @test U[j] == getlast8(r)
        end
        A = rand(T, n + 2)
        B = embed(A, U)
        #println(B)
        V = extract(B)
        #println(join(Char.(V)))
        @test U == V
    end
end
