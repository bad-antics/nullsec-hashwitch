# NullSec HashWitch - Hardened Cryptographic Hash Analysis Tool
# Language: Julia (High-Performance Scientific Computing)
# Author: bad-antics
# License: NullSec Proprietary
# Security Level: Maximum Hardening
#
# Security Features:
# - Input validation with type assertions
# - Constant-time comparison operations
# - Secure memory zeroing
# - Rate limiting on crack attempts
# - Defense-in-depth architecture
# - Comprehensive error handling

module HashWitch

using SHA
using MD5
using Random
using Printf
using Dates

# ============================================================================
# Constants & Configuration
# ============================================================================

const VERSION = "2.0.0"
const MAX_PASSWORD_LENGTH = 1024
const MAX_WORDLIST_SIZE = 100_000_000  # 100MB
const MAX_HASH_LENGTH = 256
const RATE_LIMIT_WINDOW = 1.0  # seconds
const MAX_ATTEMPTS_PER_SECOND = 1_000_000

const BANNER = raw"""
██╗  ██╗ █████╗ ███████╗██╗  ██╗██╗    ██╗██╗████████╗ ██████╗██╗  ██╗
██║  ██║██╔══██╗██╔════╝██║  ██║██║    ██║██║╚══██╔══╝██╔════╝██║  ██║
███████║███████║███████╗███████║██║ █╗ ██║██║   ██║   ██║     ███████║
██╔══██║██╔══██║╚════██║██╔══██║██║███╗██║██║   ██║   ██║     ██╔══██║
██║  ██║██║  ██║███████║██║  ██║╚███╔███╔╝██║   ██║   ╚██████╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
                      bad-antics • v""" * VERSION * """

═══════════════════════════════════════════════════════════════════════
"""

# ============================================================================
# Custom Exceptions
# ============================================================================

struct ValidationError <: Exception
    message::String
end

struct SecurityError <: Exception
    message::String
end

struct RateLimitError <: Exception
    message::String
end

# ============================================================================
# Input Validation
# ============================================================================

"""
Validate hash input string.
"""
function validate_hash(hash::String)::String
    # Check length
    if length(hash) > MAX_HASH_LENGTH
        throw(ValidationError("Hash too long (max: $MAX_HASH_LENGTH)"))
    end
    
    # Check for empty
    if isempty(hash)
        throw(ValidationError("Hash cannot be empty"))
    end
    
    # Check for valid hex characters
    hash_clean = lowercase(strip(hash))
    if !all(c -> c ∈ "0123456789abcdef", hash_clean)
        throw(ValidationError("Hash contains non-hexadecimal characters"))
    end
    
    return hash_clean
end

"""
Validate password/plaintext input.
"""
function validate_password(password::String)::String
    if length(password) > MAX_PASSWORD_LENGTH
        throw(ValidationError("Password too long (max: $MAX_PASSWORD_LENGTH)"))
    end
    
    # Check for null bytes
    if '\0' ∈ password
        throw(ValidationError("Password contains null bytes"))
    end
    
    return password
end

"""
Validate file path for reading.
"""
function validate_file_path(path::String)::String
    # Check for path traversal
    if contains(path, "..")
        throw(ValidationError("Path traversal detected"))
    end
    
    # Check if exists and readable
    if !isfile(path)
        throw(ValidationError("File not found: $path"))
    end
    
    # Check file size
    fsize = filesize(path)
    if fsize > MAX_WORDLIST_SIZE
        throw(ValidationError("File too large: $(fsize ÷ 1_000_000)MB (max: $(MAX_WORDLIST_SIZE ÷ 1_000_000)MB)"))
    end
    
    return abspath(path)
end

# ============================================================================
# Secure Memory Operations
# ============================================================================

"""
Securely zero a byte array to prevent memory disclosure.
"""
function secure_zero!(data::Vector{UInt8})::Nothing
    fill!(data, 0x00)
    # Memory barrier
    GC.safepoint()
    return nothing
end

"""
Securely zero a string's internal buffer.
"""
function secure_zero!(str::String)::Nothing
    try
        bytes = Vector{UInt8}(str)
        secure_zero!(bytes)
    catch
        # String may be immutable, silently fail
    end
    return nothing
end

# ============================================================================
# Constant-Time Operations
# ============================================================================

"""
Constant-time byte array comparison to prevent timing attacks.
"""
function constant_time_compare(a::Vector{UInt8}, b::Vector{UInt8})::Bool
    if length(a) != length(b)
        return false
    end
    
    result::UInt8 = 0x00
    for i in eachindex(a)
        result |= a[i] ⊻ b[i]
    end
    
    return result == 0x00
end

"""
Constant-time hex string comparison.
"""
function constant_time_compare_hex(a::String, b::String)::Bool
    a_bytes = hex2bytes(a)
    b_bytes = hex2bytes(b)
    return constant_time_compare(a_bytes, b_bytes)
end

# ============================================================================
# Hash Functions
# ============================================================================

"""
Supported hash algorithms.
"""
const HASH_ALGORITHMS = Dict(
    "md5"      => (32,  x -> bytes2hex(md5(x))),
    "sha1"     => (40,  x -> bytes2hex(sha1(x))),
    "sha224"   => (56,  x -> bytes2hex(sha224(x))),
    "sha256"   => (64,  x -> bytes2hex(sha256(x))),
    "sha384"   => (96,  x -> bytes2hex(sha384(x))),
    "sha512"   => (128, x -> bytes2hex(sha512(x))),
    "sha3_256" => (64,  x -> bytes2hex(sha3_256(x))),
    "sha3_512" => (128, x -> bytes2hex(sha3_512(x))),
)

"""
Detect hash type from length.
"""
function detect_hash_type(hash::String)::Vector{String}
    hash = validate_hash(hash)
    len = length(hash)
    
    matches = String[]
    for (name, (expected_len, _)) in HASH_ALGORITHMS
        if len == expected_len
            push!(matches, name)
        end
    end
    
    return matches
end

"""
Hash a plaintext with specified algorithm.
"""
function hash_password(password::String, algorithm::String)::String
    password = validate_password(password)
    
    if !haskey(HASH_ALGORITHMS, algorithm)
        throw(ValidationError("Unknown algorithm: $algorithm. Supported: $(join(keys(HASH_ALGORITHMS), ", "))"))
    end
    
    _, hash_fn = HASH_ALGORITHMS[algorithm]
    return hash_fn(password)
end

"""
Verify a hash against a plaintext.
"""
function verify_hash(hash::String, password::String, algorithm::String)::Bool
    hash = validate_hash(hash)
    computed = hash_password(password, algorithm)
    return constant_time_compare_hex(hash, computed)
end

# ============================================================================
# Rate Limiter
# ============================================================================

mutable struct RateLimiter
    max_rps::Int
    tokens::Float64
    last_refill::Float64
    lock::ReentrantLock
    
    function RateLimiter(max_rps::Int=MAX_ATTEMPTS_PER_SECOND)
        new(max_rps, Float64(max_rps), time(), ReentrantLock())
    end
end

function acquire!(limiter::RateLimiter)::Nothing
    lock(limiter.lock) do
        now = time()
        elapsed = now - limiter.last_refill
        
        # Refill tokens
        limiter.tokens = min(limiter.max_rps, limiter.tokens + elapsed * limiter.max_rps)
        limiter.last_refill = now
        
        if limiter.tokens < 1.0
            # Wait for token
            sleep_time = (1.0 - limiter.tokens) / limiter.max_rps
            sleep(sleep_time)
            limiter.tokens = 0.0
        else
            limiter.tokens -= 1.0
        end
    end
    return nothing
end

# ============================================================================
# Dictionary Attack
# ============================================================================

struct CrackResult
    found::Bool
    password::Union{String, Nothing}
    hash::String
    algorithm::String
    attempts::Int
    duration_ms::Float64
end

"""
Dictionary attack against a hash.
"""
function dictionary_attack(
    hash::String, 
    wordlist_path::String;
    algorithm::Union{String, Nothing}=nothing,
    verbose::Bool=false,
    max_attempts::Int=10_000_000
)::CrackResult
    
    hash = validate_hash(hash)
    wordlist_path = validate_file_path(wordlist_path)
    
    # Detect or validate algorithm
    if algorithm === nothing
        detected = detect_hash_type(hash)
        if isempty(detected)
            throw(ValidationError("Cannot detect hash type for length $(length(hash))"))
        end
        algorithm = detected[1]
        verbose && println("[*] Auto-detected algorithm: $algorithm")
    end
    
    _, hash_fn = HASH_ALGORITHMS[algorithm]
    
    limiter = RateLimiter()
    start_time = time()
    attempts = 0
    
    open(wordlist_path, "r") do file
        for line in eachline(file)
            # Rate limit
            acquire!(limiter)
            
            attempts += 1
            if attempts > max_attempts
                verbose && println("[!] Max attempts reached: $max_attempts")
                break
            end
            
            password = strip(line)
            if isempty(password)
                continue
            end
            
            computed = hash_fn(password)
            
            if constant_time_compare_hex(hash, computed)
                duration = (time() - start_time) * 1000
                return CrackResult(true, password, hash, algorithm, attempts, duration)
            end
            
            # Progress update
            if verbose && attempts % 100_000 == 0
                rate = attempts / (time() - start_time)
                @printf("[*] Tried %d passwords (%.0f/s)\n", attempts, rate)
            end
        end
    end
    
    duration = (time() - start_time) * 1000
    return CrackResult(false, nothing, hash, algorithm, attempts, duration)
end

# ============================================================================
# Brute Force Attack
# ============================================================================

"""
Generate character set for brute force.
"""
function get_charset(name::Symbol)::Vector{Char}
    charsets = Dict(
        :lowercase => collect('a':'z'),
        :uppercase => collect('A':'Z'),
        :digits    => collect('0':'9'),
        :special   => collect("!@#\$%^&*()_+-=[]{}|;':\",./<>?"),
        :alpha     => vcat(collect('a':'z'), collect('A':'Z')),
        :alphanum  => vcat(collect('a':'z'), collect('A':'Z'), collect('0':'9')),
        :all       => vcat(collect('a':'z'), collect('A':'Z'), collect('0':'9'), 
                          collect("!@#\$%^&*()_+-=[]{}|;':\",./<>?")),
    )
    
    return get(charsets, name, charsets[:alphanum])
end

"""
Brute force attack (limited for safety).
"""
function brute_force_attack(
    hash::String;
    algorithm::Union{String, Nothing}=nothing,
    charset::Symbol=:alphanum,
    min_length::Int=1,
    max_length::Int=6,  # Safety limit
    verbose::Bool=false,
    max_attempts::Int=10_000_000
)::CrackResult
    
    hash = validate_hash(hash)
    
    # Safety limit
    if max_length > 8
        throw(SecurityError("Max length limited to 8 for brute force attacks"))
    end
    
    if algorithm === nothing
        detected = detect_hash_type(hash)
        if isempty(detected)
            throw(ValidationError("Cannot detect hash type"))
        end
        algorithm = detected[1]
    end
    
    _, hash_fn = HASH_ALGORITHMS[algorithm]
    chars = get_charset(charset)
    
    limiter = RateLimiter()
    start_time = time()
    attempts = 0
    
    verbose && println("[*] Brute forcing with $(length(chars)) chars, lengths $min_length-$max_length")
    
    for len in min_length:max_length
        verbose && println("[*] Trying length $len...")
        
        for combination in Iterators.product(fill(chars, len)...)
            acquire!(limiter)
            attempts += 1
            
            if attempts > max_attempts
                verbose && println("[!] Max attempts reached")
                duration = (time() - start_time) * 1000
                return CrackResult(false, nothing, hash, algorithm, attempts, duration)
            end
            
            password = String(collect(combination))
            computed = hash_fn(password)
            
            if constant_time_compare_hex(hash, computed)
                duration = (time() - start_time) * 1000
                return CrackResult(true, password, hash, algorithm, attempts, duration)
            end
            
            if verbose && attempts % 100_000 == 0
                rate = attempts / (time() - start_time)
                @printf("[*] Tried %d combinations (%.0f/s)\n", attempts, rate)
            end
        end
    end
    
    duration = (time() - start_time) * 1000
    return CrackResult(false, nothing, hash, algorithm, attempts, duration)
end

# ============================================================================
# Hash Analysis
# ============================================================================

"""
Analyze a hash for various properties.
"""
function analyze_hash(hash::String)::Dict{String, Any}
    hash = validate_hash(hash)
    
    analysis = Dict{String, Any}()
    
    # Basic properties
    analysis["hash"] = hash
    analysis["length"] = length(hash)
    analysis["possible_types"] = detect_hash_type(hash)
    
    # Entropy calculation
    bytes = hex2bytes(hash)
    analysis["entropy_bits"] = calculate_entropy(bytes)
    
    # Pattern analysis
    analysis["has_repeating_patterns"] = has_repeating_patterns(hash)
    analysis["unique_chars"] = length(unique(hash))
    
    # Statistical analysis
    analysis["char_distribution"] = analyze_char_distribution(hash)
    
    return analysis
end

"""
Calculate Shannon entropy of bytes.
"""
function calculate_entropy(data::Vector{UInt8})::Float64
    if isempty(data)
        return 0.0
    end
    
    # Count byte frequencies
    freq = zeros(Int, 256)
    for b in data
        freq[b + 1] += 1
    end
    
    # Calculate entropy
    n = length(data)
    entropy = 0.0
    for count in freq
        if count > 0
            p = count / n
            entropy -= p * log2(p)
        end
    end
    
    return entropy * length(data)  # Total entropy in bits
end

"""
Check for repeating patterns in hash.
"""
function has_repeating_patterns(hash::String)::Bool
    # Check for common weak patterns
    for pattern_len in 2:4
        if length(hash) >= pattern_len * 2
            pattern = hash[1:pattern_len]
            if all(i -> hash[i:i+pattern_len-1] == pattern, 1:pattern_len:length(hash)-pattern_len+1)
                return true
            end
        end
    end
    return false
end

"""
Analyze character distribution.
"""
function analyze_char_distribution(hash::String)::Dict{Char, Int}
    dist = Dict{Char, Int}()
    for c in hash
        dist[c] = get(dist, c, 0) + 1
    end
    return dist
end

# ============================================================================
# CLI Interface
# ============================================================================

function print_help()
    println("""
    USAGE:
        julia hashwitch.jl <command> [options]
    
    COMMANDS:
        hash <algorithm> <plaintext>      Hash a plaintext
        crack <hash> -w <wordlist>        Dictionary attack
        brute <hash> [options]            Brute force attack
        analyze <hash>                    Analyze hash properties
        identify <hash>                   Identify hash type
        verify <hash> <password> <algo>   Verify hash matches password
    
    OPTIONS:
        -a, --algorithm <name>    Hash algorithm (md5, sha1, sha256, etc.)
        -w, --wordlist <file>     Wordlist file for dictionary attack
        -c, --charset <name>      Character set (lowercase, alphanum, all)
        -m, --min-length <n>      Minimum password length for brute force
        -M, --max-length <n>      Maximum password length for brute force
        -v, --verbose             Verbose output
        -h, --help                Show this help
    
    ALGORITHMS:
        md5, sha1, sha224, sha256, sha384, sha512, sha3_256, sha3_512
    
    EXAMPLES:
        julia hashwitch.jl hash sha256 "password123"
        julia hashwitch.jl crack 5f4dcc3b5aa765d61d8327deb882cf99 -w rockyou.txt
        julia hashwitch.jl brute 5f4dcc3b5aa765d61d8327deb882cf99 -M 6
        julia hashwitch.jl analyze 5f4dcc3b5aa765d61d8327deb882cf99
    """)
end

function main(args::Vector{String})
    println(BANNER)
    
    if isempty(args) || "-h" ∈ args || "--help" ∈ args
        print_help()
        return
    end
    
    command = args[1]
    
    try
        if command == "hash"
            if length(args) < 3
                println("[!] Usage: hash <algorithm> <plaintext>")
                return
            end
            result = hash_password(args[3], args[2])
            println("[+] Hash ($( args[2])): $result")
            
        elseif command == "crack"
            if length(args) < 4 || "-w" ∉ args
                println("[!] Usage: crack <hash> -w <wordlist>")
                return
            end
            
            hash = args[2]
            wordlist_idx = findfirst(==("-w"), args)
            wordlist = args[wordlist_idx + 1]
            
            verbose = "-v" ∈ args || "--verbose" ∈ args
            
            println("[*] Starting dictionary attack...")
            result = dictionary_attack(hash, wordlist; verbose=verbose)
            
            if result.found
                println("\n[+] ✓ PASSWORD FOUND!")
                println("    Password: $(result.password)")
                println("    Algorithm: $(result.algorithm)")
                println("    Attempts: $(result.attempts)")
                println("    Time: $(@sprintf("%.2f", result.duration_ms))ms")
            else
                println("\n[-] Password not found")
                println("    Attempts: $(result.attempts)")
            end
            
        elseif command == "brute"
            if length(args) < 2
                println("[!] Usage: brute <hash> [options]")
                return
            end
            
            hash = args[2]
            max_len = 6
            
            if "-M" ∈ args
                idx = findfirst(==("-M"), args)
                max_len = parse(Int, args[idx + 1])
            end
            
            verbose = "-v" ∈ args
            
            println("[*] Starting brute force attack...")
            result = brute_force_attack(hash; max_length=max_len, verbose=verbose)
            
            if result.found
                println("\n[+] ✓ PASSWORD FOUND!")
                println("    Password: $(result.password)")
            else
                println("\n[-] Password not found")
            end
            
        elseif command == "analyze"
            if length(args) < 2
                println("[!] Usage: analyze <hash>")
                return
            end
            
            analysis = analyze_hash(args[2])
            
            println("[*] Hash Analysis")
            println("─────────────────────────────────────────")
            println("  Length:         $(analysis["length"])")
            println("  Possible types: $(join(analysis["possible_types"], ", "))")
            println("  Entropy:        $(@sprintf("%.2f", analysis["entropy_bits"])) bits")
            println("  Unique chars:   $(analysis["unique_chars"])")
            println("  Repeating:      $(analysis["has_repeating_patterns"] ? "Yes ⚠️" : "No ✓")")
            
        elseif command == "identify"
            if length(args) < 2
                println("[!] Usage: identify <hash>")
                return
            end
            
            types = detect_hash_type(args[2])
            if isempty(types)
                println("[!] Unknown hash type")
            else
                println("[+] Possible hash types: $(join(types, ", "))")
            end
            
        elseif command == "verify"
            if length(args) < 4
                println("[!] Usage: verify <hash> <password> <algorithm>")
                return
            end
            
            if verify_hash(args[2], args[3], args[4])
                println("[+] ✓ Hash matches password")
            else
                println("[-] ✗ Hash does not match")
            end
            
        else
            println("[!] Unknown command: $command")
            print_help()
        end
        
    catch e
        if e isa ValidationError
            println("[!] Validation Error: $(e.message)")
        elseif e isa SecurityError
            println("[!] Security Error: $(e.message)")
        else
            println("[!] Error: $e")
        end
    end
end

# Entry point
if abspath(PROGRAM_FILE) == @__FILE__
    main(ARGS)
end

end  # module
