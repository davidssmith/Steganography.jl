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

# steganography of single precision float arrays

function setlast8{T}(x::T, n::UInt8)
    i = reinterpret(Unsigned, x)
    i = (i >> 8) << 8
    i = i | n
    reinterpret(T, i)
end

function setlast7{T}(x::T, n::UInt8)
    i = reinterpret(Unsigned, x)
    i = (i >> 7) << 7
    i = i | (n & 0x7f)
    reinterpret(T, i)
end

function setlastbits{T}(x::T, n::UInt8, nbits::UInt8)
    i = reinterpret(Unsigned, x)
    S = typeof(i)
    i = (i >> nbits) << nbits
    i = i | (n & ((S(1) << nbits) - S(1)))
    reinterpret(T, i)
end

getlast8{T}(x::T) = UInt8(reinterpret(Unsigned, x) & 0xff)
getlast7{T}(x::T) = UInt8(reinterpret(Unsigned, x) & 0x7f)

function getlastbits{T}(x::T, nbits::UInt8)
    i = reinterpret(Unsigned, x)
    S = typeof(i)
    return UInt8(i & ((S(1) << nbits) - S(1)))
end

function embed{N}(data::Array{Float32,N}, text::Array{UInt8,1}; ignorenonascii::Bool=true)
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

function extract{N}(data::Array{Float32,N})
    s = reinterpret(UInt32, data)
    s = UInt8.(s .& 0x7f)
    n = findfirst(x -> x == 0x04, s)
    t[1:n-1]
end

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
