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

using Compat

export embed, extract, setlastbits, getlastbits, setlast7, setlast8, 
    getlast7, getlast8

const version = v"0.0.1"


function flattencomplex{T<:Complex,N}(x::Array{T,N})
    if T == Complex128
        T2 = Float64
    elseif T == Complex64
        T2 = Float32
    elseif T == Complex32
        T2 = Float16
    else
        error("unhandled Complex type")
    end
    y = Array{T2}(2length(x))
    for k in 1:length(x)
        y[2k-1] = real(x[k])
        y[2k] = imag(x[k])
    end
    return y
end
function unflattencomplex{T<:Real,N}(y::Array{T,N})
    if T == Float64
        T2 = Complex128
    elseif T == Float32
        T2 = Complex64
    elseif T == Float16
        T2 = Complex32
    else
        error("unhandled Complex type")
    end
    x = Array{T2}(div(length(y),2))
    for k in 1:length(x)
        x[k] = complex(y[2k-1],y[2k])
    end
    return x
end

@compat function setlastbits{T<:Integer}(i::T, n::UInt8, nbits::UInt8)
    S = typeof(i)
    j = (i >> nbits) << nbits
    j | (n & ((S(1) << nbits) - S(1)))
end
@compat setlastbits{T<:AbstractFloat}(x::T, n::UInt8, nbits::UInt8) = reinterpret(T, setlastbits(reinterpret(Unsigned, x), n, nbits))
@compat setlast8{T}(x::T, n::UInt8) = setlastbits(x, n, UInt8(8))
@compat setlast7{T}(x::T, n::UInt8) = setlastbits(x, n, UInt8(7))

@compat function getlastbits{T}(i::T, nbits::UInt8)
    S = typeof(i)
    return UInt8(i & ((S(1) << nbits) - S(1)))
end
@compat getlastbits{T<:AbstractFloat}(x::T, nbits::UInt8) = getlastbits(reinterpret(Unsigned, x), nbits)

@compat getlast8{T<:AbstractFloat}(x::T) = UInt8(reinterpret(Unsigned, x) & 0xff)
@compat getlast8{T}(x::T) = UInt8(x & 0xff)   # catch all

@compat getlast7{T<:AbstractFloat}(x::T) = UInt8(reinterpret(Unsigned, x) & 0x7f)
@compat getlast7{T}(x::T) = UInt8(x & 0x7f)   # catch all

@compat function embed{T,N}(data::Array{T,N}, text::Array{UInt8,1}; ignorenonascii::Bool=true)
    if T <: Complex
        data = flattencomplex(data)
    end
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
    if T <: Complex
        return unflattencomplex(y)
    else
        return y
    end
end

@compat function extract{T,N}(s::Array{T,N})
    if T <: Complex
        s = flattencomplex(s)
   end
    t = Array{UInt8}(length(s))
    k = 1
    while true
        t[k] = getlast7(s[k])
        if t[k] == 0x04
            break
        end
        k += 1
    end
    t[1:k-1]
end

end
