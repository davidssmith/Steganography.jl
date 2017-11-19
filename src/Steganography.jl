# This file is part of the Steganography package 
# (http://github.com/davidssmith/Steganography.jl).
#
# The MIT License (MIT)
#
# Copyright (c) 2017 David Smith
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


module Steganography

export embed, extract, setlastbits, getlastbits, setlast7, setlast8, 
    getlast7, getlast8

const version = v"0.0.1"

function setlastbits{T<:Integer}(i::T, n::UInt8, nbits::UInt8)
    S = typeof(i)
    j = (i >> nbits) << nbits
    j | (n & ((S(1) << nbits) - S(1)))
end
setlastbits{T<:AbstractFloat}(x::T, n::UInt8, nbits::UInt8) = reinterpret(T, setlastbits(reinterpret(Unsigned, x), n, nbits))
setlast8{T}(x::T, n::UInt8) = setlastbits(x, n, UInt8(8))
setlast7{T}(x::T, n::UInt8) = setlastbits(x, n, UInt8(7))

function getlastbits{T}(i::T, nbits::UInt8)
    S = typeof(i)
    return UInt8(i & ((S(1) << nbits) - S(1)))
end
getlastbits{T<:AbstractFloat}(x::T, nbits::UInt8) = getlastbits(reinterpret(Unsigned, x), nbits)
getlast8{T<:AbstractFloat}(x::T) = UInt8(reinterpret(Unsigned, x) & 0xff)
getlast7{T<:AbstractFloat}(x::T) = UInt8(reinterpret(Unsigned, x) & 0x7f)
getlast8{T}(x::T) = UInt8(x & 0xff)
getlast7{T}(x::T) = UInt8(x & 0x7f)

function embed{T,N}(data::Array{T,N}, text::Array{UInt8,1}; ignorenonascii::Bool=true)
    @assert length(text) <= length(data)
    y = copy(data)   # make sure we have enough space
    for j in 1:length(text)
        @assert text[j] != 0x04
        if !ignorenonascii
            @assert text[j] <= 0x7f
        end
        if text[j] > 0x7f
            println(text[j], " ", Char(text[j]), " ", hex(text[j]))
            y[j] = setlast7(data[j], UInt8(0))
        else
            y[j] = setlast7(data[j], text[j])
        end
    end
    if length(text) < length(data)
        y[length(text)+1] = setlast7(data[length(text)+1], 0x04) # ASCII 0x04 means 'end of transmission'
    end
    y
end

function embed{N}(data::Array{Complex64,N}, text::Array{UInt8,1}; ina::Bool=true)
    d = size(data)
    y = reinterpret(Float32, data[:])
    y = embed(y, text; ignorenonascii=ina)
    y = reinterpret(Complex64, y[:])
    reshape(y, d)
end

function extract{T<:Integer,N}(s::Array{T,N})
    s = UInt8.(s .& 0x7f)
    n = findfirst(x -> x == 0x04, s)
    s[1:n-1]
end
extract{N}(data::Array{Float32,N}) = extract(reinterpret(UInt32, data))
extract{N}(data::Array{Float64,N}) = extract(reinterpret(UInt64, data))

function extract{N}(data::Array{Complex64,N})
    d = size(data)
    s = reinterpret(Float32, data[:])
    s = reinterpret(UInt32, s)
    s = UInt8.(s .& 0x7f)
    n = findfirst(x -> x == 0x04, s)
    println("found 0x04 at $n")
    s[1:n-1]
end


end
