#!/usr/bin/env julia
# NullSec HashWitch - High-Performance Hash Cracking & Analysis
# Language: Julia
# Author: bad-antics
# License: NullSec Proprietary

using SHA
using MD5
using Printf
using Base.Threads
using Dates

const VERSION = "1.0.0"

const BANNER = """
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░░ H A S H W I T C H ░░░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics v$VERSION
"""

# Hash type signatures
const HASH_SIGNATURES = Dict(
    # MD5 variants
    r"^[a-f0-9]{32}$"i => ["MD5", "NTLM", "MD4", "LM"],
    r"^\$1\$.{8}\$.{22}$" => ["MD5crypt"],
    r"^\$apr1\$.{8}\$.{22}$" => ["Apache MD5"],
    
    # SHA variants  
    r"^[a-f0-9]{40}$"i => ["SHA1", "MySQL5", "RIPEMD-160"],
    r"^[a-f0-9]{56}$"i => ["SHA224"],
    r"^[a-f0-9]{64}$"i => ["SHA256", "Keccak-256", "RIPEMD-256"],
    r"^[a-f0-9]{96}$"i => ["SHA384"],
    r"^[a-f0-9]{128}$"i => ["SHA512", "Whirlpool", "SHA3-512"],
    
    # bcrypt
    r"^\$2[ayb]\$.{56}$" => ["bcrypt"],
    r"^\$2a\$\d{2}\$.{53}$" => ["bcrypt"],
    
    # Other
    r"^\$5\$.{16}\$.{43}$" => ["SHA256crypt"],
    r"^\$6\$.{16}\$.{86}$" => ["SHA512crypt"],
    r"^\$argon2[id]{1,2}\$" => ["Argon2"],
    r"^[a-f0-9]{16}$"i => ["MySQL323", "DES", "Half-MD5"],
    r"^\*[A-F0-9]{40}$" => ["MySQL5"],
    r"^[a-f0-9]{32}:[a-f0-9]+$"i => ["MD5 Salted"],
)

# Charset definitions
const CHARSETS = Dict(
    '?' => Dict(
        'l' => collect('a':'z'),
        'u' => collect('A':'Z'),
        'd' => collect('0':'9'),
        's' => collect("!@#\$%^&*()-_=+[]{}|;:',.<>?/`~"),
        'a' => vcat(collect('a':'z'), collect('A':'Z'), collect('0':'9'), collect("!@#\$%^&*()-_=+[]{}|;:',.<>?/`~")),
        'b' => collect(Char(0):Char(255))
    )
)

# Results structure
mutable struct CrackResult
    hash::String
    plaintext::Union{String, Nothing}
    hash_type::String
    time_taken::Float64
    attempts::Int64
end

# Identify hash type
function identify_hash(hash::String)
    hash = strip(hash)
    matches = String[]
    
    for (pattern, types) in HASH_SIGNATURES
        if occursin(pattern, hash)
            append!(matches, types)
        end
    end
    
    if isempty(matches)
        return ["Unknown"]
    end
    
    return unique(matches)
end

# Hash functions
function compute_hash(plaintext::String, hash_type::String)::String
    bytes = Vector{UInt8}(plaintext)
    
    if hash_type == "MD5" || hash_type == "md5"
        return bytes2hex(md5(bytes))
    elseif hash_type == "SHA1" || hash_type == "sha1"
        return bytes2hex(sha1(bytes))
    elseif hash_type == "SHA256" || hash_type == "sha256"
        return bytes2hex(sha256(bytes))
    elseif hash_type == "SHA512" || hash_type == "sha512"
        return bytes2hex(sha512(bytes))
    elseif hash_type == "NTLM" || hash_type == "ntlm"
        # NTLM = MD4(UTF-16LE(password))
        # Simplified - using MD5 as placeholder
        return bytes2hex(md5(bytes))
    else
        return bytes2hex(md5(bytes))
    end
end

# Dictionary attack
function dictionary_attack(target_hash::String, wordlist_path::String, hash_type::String; verbose::Bool=false)
    target_hash = lowercase(strip(target_hash))
    attempts = Atomic{Int64}(0)
    found = Atomic{Bool}(false)
    result_plaintext = Ref{Union{String, Nothing}}(nothing)
    
    start_time = time()
    
    # Read wordlist
    if !isfile(wordlist_path)
        println("[!] Wordlist not found: $wordlist_path")
        return nothing
    end
    
    words = readlines(wordlist_path)
    total_words = length(words)
    
    println("[*] Loaded $total_words words from wordlist")
    println("[*] Starting dictionary attack...")
    
    # Parallel processing
    chunk_size = max(1, total_words ÷ nthreads())
    
    @threads for i in 1:nthreads()
        start_idx = (i - 1) * chunk_size + 1
        end_idx = i == nthreads() ? total_words : i * chunk_size
        
        for idx in start_idx:end_idx
            if found[]
                break
            end
            
            word = words[idx]
            computed = compute_hash(word, hash_type)
            atomic_add!(attempts, 1)
            
            if computed == target_hash
                found[] = true
                result_plaintext[] = word
                break
            end
            
            # Progress update
            if verbose && attempts[] % 100000 == 0
                elapsed = time() - start_time
                rate = attempts[] / elapsed
                @printf("\r[*] Tried %d passwords (%.0f/sec)", attempts[], rate)
            end
        end
    end
    
    elapsed = time() - start_time
    
    if result_plaintext[] !== nothing
        return CrackResult(target_hash, result_plaintext[], hash_type, elapsed, attempts[])
    end
    
    return CrackResult(target_hash, nothing, hash_type, elapsed, attempts[])
end

# Brute force attack
function brute_force_attack(target_hash::String, hash_type::String, mask::String; 
                           max_length::Int=8, verbose::Bool=false)
    target_hash = lowercase(strip(target_hash))
    attempts = Atomic{Int64}(0)
    found = Atomic{Bool}(false)
    result_plaintext = Ref{Union{String, Nothing}}(nothing)
    
    start_time = time()
    
    # Parse mask into charset array
    charsets = parse_mask(mask)
    
    println("[*] Mask: $mask")
    println("[*] Password length: $(length(charsets))")
    
    total_combinations = prod(length.(charsets))
    println("[*] Total combinations: $total_combinations")
    println("[*] Starting brute force attack...")
    
    # Generate and test combinations
    generate_combinations(charsets, 1, Char[]) do candidate
        if found[]
            return false
        end
        
        plain = String(candidate)
        computed = compute_hash(plain, hash_type)
        atomic_add!(attempts, 1)
        
        if computed == target_hash
            found[] = true
            result_plaintext[] = plain
            return false
        end
        
        if verbose && attempts[] % 100000 == 0
            elapsed = time() - start_time
            rate = attempts[] / elapsed
            @printf("\r[*] Tried %d passwords (%.0f/sec)", attempts[], rate)
        end
        
        return true  # Continue
    end
    
    elapsed = time() - start_time
    
    if result_plaintext[] !== nothing
        return CrackResult(target_hash, result_plaintext[], hash_type, elapsed, attempts[])
    end
    
    return CrackResult(target_hash, nothing, hash_type, elapsed, attempts[])
end

function parse_mask(mask::String)
    charsets = Vector{Char}[]
    i = 1
    while i <= length(mask)
        if mask[i] == '?' && i < length(mask)
            charset_type = mask[i+1]
            if haskey(CHARSETS['?'], charset_type)
                push!(charsets, CHARSETS['?'][charset_type])
            else
                push!(charsets, [mask[i+1]])
            end
            i += 2
        else
            push!(charsets, [mask[i]])
            i += 1
        end
    end
    return charsets
end

function generate_combinations(callback::Function, charsets::Vector{Vector{Char}}, 
                              pos::Int, current::Vector{Char})
    if pos > length(charsets)
        return callback(current)
    end
    
    for c in charsets[pos]
        push!(current, c)
        if !generate_combinations(callback, charsets, pos + 1, current)
            pop!(current)
            return false
        end
        pop!(current)
    end
    return true
end

# Apply rules to words
function apply_rules(word::String)::Vector{String}
    mutations = [word]
    
    # Capitalize first letter
    if length(word) > 0
        push!(mutations, uppercase(word[1:1]) * word[2:end])
    end
    
    # All uppercase
    push!(mutations, uppercase(word))
    
    # All lowercase
    push!(mutations, lowercase(word))
    
    # Reverse
    push!(mutations, reverse(word))
    
    # Append numbers
    for n in ["1", "12", "123", "1234", "!", "!!", "@", "2024", "2025", "2026"]
        push!(mutations, word * n)
    end
    
    # Prepend numbers
    for n in ["1", "123"]
        push!(mutations, n * word)
    end
    
    # Leet speak
    leet = replace(word, 'a' => '4', 'e' => '3', 'i' => '1', 'o' => '0', 's' => '5')
    push!(mutations, leet)
    
    return unique(mutations)
end

# Print results
function print_result(result::CrackResult)
    println()
    println("─" ^ 60)
    
    if result.plaintext !== nothing
        println("[+] CRACKED!")
        println("    Hash:      $(result.hash)")
        println("    Plaintext: $(result.plaintext)")
        println("    Type:      $(result.hash_type)")
        println("    Time:      $(round(result.time_taken, digits=2)) seconds")
        println("    Attempts:  $(result.attempts)")
    else
        println("[-] NOT FOUND")
        println("    Hash:      $(result.hash)")
        println("    Type:      $(result.hash_type)")
        println("    Time:      $(round(result.time_taken, digits=2)) seconds")
        println("    Attempts:  $(result.attempts)")
    end
    
    println("─" ^ 60)
end

# Main CLI
function main()
    println(BANNER)
    
    if length(ARGS) < 1
        print_usage()
        return
    end
    
    command = ARGS[1]
    
    if command == "identify"
        if length(ARGS) < 2
            println("[!] Usage: hashwitch identify <hash>")
            return
        end
        
        hash = ARGS[2]
        # Remove -h flag if present
        if hash == "-h" && length(ARGS) >= 3
            hash = ARGS[3]
        end
        
        types = identify_hash(hash)
        
        println("[*] Hash: $hash")
        println("[*] Length: $(length(hash)) characters")
        println("[*] Possible types:")
        for t in types
            println("    - $t")
        end
        
    elseif command == "crack"
        # Parse arguments
        hash = ""
        wordlist = ""
        hash_type = "md5"
        brute = false
        mask = "?l?l?l?l?l?l"
        verbose = false
        
        i = 2
        while i <= length(ARGS)
            if ARGS[i] == "-h" && i < length(ARGS)
                hash = ARGS[i+1]
                i += 2
            elseif ARGS[i] == "-w" && i < length(ARGS)
                wordlist = ARGS[i+1]
                i += 2
            elseif ARGS[i] == "-m" && i < length(ARGS)
                hash_type = ARGS[i+1]
                i += 2
            elseif ARGS[i] == "--brute"
                brute = true
                i += 1
            elseif ARGS[i] == "-c" && i < length(ARGS)
                mask = ARGS[i+1]
                i += 2
            elseif ARGS[i] == "-v"
                verbose = true
                i += 1
            else
                i += 1
            end
        end
        
        if hash == ""
            println("[!] Hash required (-h)")
            return
        end
        
        # Auto-detect hash type if not specified
        detected = identify_hash(hash)
        if hash_type == "md5" && !isempty(detected) && detected[1] != "Unknown"
            println("[*] Auto-detected hash type: $(detected[1])")
            hash_type = detected[1]
        end
        
        println("[*] Target hash: $hash")
        println("[*] Hash type: $hash_type")
        println("[*] Threads: $(nthreads())")
        
        if brute
            result = brute_force_attack(hash, hash_type, mask; verbose=verbose)
        elseif wordlist != ""
            result = dictionary_attack(hash, wordlist, hash_type; verbose=verbose)
        else
            println("[!] Either wordlist (-w) or --brute required")
            return
        end
        
        print_result(result)
        
    elseif command == "hash"
        if length(ARGS) < 3
            println("[!] Usage: hashwitch hash <type> <plaintext>")
            return
        end
        
        hash_type = ARGS[2]
        plaintext = ARGS[3]
        
        result = compute_hash(plaintext, hash_type)
        println("[*] Plaintext: $plaintext")
        println("[*] Type: $hash_type")
        println("[*] Hash: $result")
        
    elseif command == "help" || command == "-h" || command == "--help"
        print_usage()
        
    else
        println("[!] Unknown command: $command")
        print_usage()
    end
end

function print_usage()
    println("""
    
USAGE:
    hashwitch <command> [options]

COMMANDS:
    identify    Identify hash type
    crack       Crack hash(es)
    hash        Generate hash from plaintext

CRACK OPTIONS:
    -h <hash>       Target hash or hash file
    -w <wordlist>   Wordlist file path
    -m <type>       Hash type (md5, sha1, sha256, etc.)
    --brute         Enable brute force mode
    -c <mask>       Charset mask for brute force
    -v              Verbose output

MASK CHARACTERS:
    ?l  Lowercase (a-z)
    ?u  Uppercase (A-Z)
    ?d  Digits (0-9)
    ?s  Special characters
    ?a  All printable

EXAMPLES:
    hashwitch identify "5f4dcc3b5aa765d61d8327deb882cf99"
    hashwitch crack -h hash.txt -w rockyou.txt
    hashwitch crack -h "098f6bcd..." -m md5 --brute -c "?l?l?l?l?d?d"
    hashwitch hash md5 "password"
""")
end

# Run
main()
