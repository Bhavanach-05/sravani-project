import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "quantumshield_super_secure_master_key_2026")
    JWT_SECRET = os.environ.get("JWT_SECRET", "quantumshield_jwt_pq_secret_key_2026")
    DATABASE_PATH = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "quantumshield.db"))
    
    # Ring-LWE Post-Quantum Parameters
    # Standard Kyber-aligned lattice parameters: n=256, q=3329 (prime q == 1 mod 2n)
    RLWE_N = 256
    RLWE_Q = 3329
    RLWE_ETA = 2  # Centered Binomial Distribution width (small discrete Gaussian simulation)
    RLWE_THRESHOLD = 550  # Bounded error tolerance for challenge-response lattice verification
    
    # Wang-Wang Fuzzy Verifier Parameters
    FUZZY_SECRET_LEN = 16  # 128-bit smart card secret representation
    FUZZY_TOLERANCE = 2    # Maximum allowed byte/bit difference for error-tolerant reconstruction
    
    # Smart Card Attack Detection (SCAD) Thresholds
    SCAD_MAX_FAILED_ATTEMPTS = 3     # Max card failures before lock
    SCAD_RAPID_FIRE_WINDOW = 10      # Seconds to inspect for rapid burst attacks
    SCAD_RAPID_FIRE_THRESHOLD = 4   # Attempts within window triggering alert
    SCAD_LOCK_DURATION_SECONDS = 900 # 15 minutes lock
    
    # Session Settings
    STAGE_TOKEN_TTL_SECONDS = 300    # 5 minutes to complete next stage
    SESSION_TTL_SECONDS = 3600       # 1 hour active session lifetime
