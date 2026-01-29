import discord
from discord import app_commands
from discord.ext import commands, tasks
from discord.enums import AuditLogAction
from collections import deque
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Set, Tuple, List
import asyncio
import json
import time
import hashlib
import logging
import random

# Config
TOKEN = ""

# Thresholds
THRESHOLDS = {
    "channel_delete": 2,
    "role_delete": 1,
    "member_ban": 3,
    "member_kick": 5,
    "channel_create": 8,
    "role_create": 5,
}

# Multi-executor detection
GUILD_BURST_WINDOW = 0.5
GUILD_BURST_THRESHOLD = 3
DISTRIBUTED_ATTACK_WINDOW = 2.0

# Slow nuke detection
SLOW_NUKE_WINDOWS = [30, 120, 300]  # 30s, 2min, 5min
SLOW_NUKE_THRESHOLDS = {
    30: {"channel_delete": 4, "role_delete": 2},
    120: {"channel_delete": 8, "role_delete": 4},
    300: {"channel_delete": 15, "role_delete": 8},
}

# Fingerprinting
FINGERPRINT_WINDOW = 10.0
FINGERPRINT_MATCH_THRESHOLD = 0.75

# Shadow mitigation
SHADOW_MODE_ENABLED = True
SHADOW_MODE_DELAY_MIN = 5
SHADOW_MODE_DELAY_MAX = 30

# Intent tracking (long-term)
INTENT_DECAY_HOURS = 24
INTENT_CRITICAL_THRESHOLD = 0.7

# Staging detection
STAGING_INDICATORS = {
    "bulk_role_create": 3,
    "suspicious_role_names": ["test", "temp", "new"],
    "permission_changes": 2,
}

# Internal rate limits
INTERNAL_RATE_LIMITS = {
    "channel_delete": (1, 5),  # 1 per 5 seconds
    "role_delete": (1, 10),
    "member_ban": (2, 10),
}

# Probabilistic jitter
JITTER_ENABLED = True
JITTER_RANGE = 0.15  # 15% variation

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('DefensiveBot')

# ============================================================================
# STATE MANAGEMENT
# ============================================================================

class DefensiveState:
    """Complete state management."""
    
    def __init__(self):
        # Core tracking
        self.events: Dict[int, Dict[str, deque]] = {}
        self.guild_events: Dict[int, deque] = {}  # Guild-wide events
        self.scores: Dict[int, Dict[int, float]] = {}
        self.last_score_update: Dict[int, Dict[int, float]] = {}
        
        # Multi-executor correlation
        self.distributed_events: Dict[int, Dict[str, List[Tuple[float, int]]]] = {}
        
        # Fingerprinting
        self.attack_fingerprints: Dict[int, List[Tuple[str, float]]] = {}
        self.known_tool_signatures: Dict[str, Dict] = {}
        
        # Slow nuke tracking
        self.slow_nuke_counters: Dict[int, Dict[int, Dict[int, int]]] = {}
        
        # Shadow mitigation
        self.shadow_queue: Dict[int, List[Tuple[int, str, float]]] = {}
        self.silent_restrictions: Dict[int, Dict[int, Set[str]]] = {}
        
        # Backup integrity
        self.backups: Dict[int, List[Dict]] = {}
        self.backup_hashes: Dict[int, List[str]] = {}
        
        # Trust chain
        self.permission_chain: Dict[int, Dict[int, List[Tuple[int, float]]]] = {}
        
        # Long-term intent
        self.intent_history: Dict[int, Dict[int, List[Tuple[float, float]]]] = {}
        
        # Staging detection
        self.staging_signals: Dict[int, Dict[int, List[Tuple[float, str]]]] = {}
        
        # Internal rate limits
        self.rate_limit_state: Dict[int, Dict[int, Dict[str, deque]]] = {}
        
        # Audit log verification
        self.audit_log_sequence: Dict[int, deque] = {}
        self.audit_log_anomalies: Dict[int, int] = {}
        
        # Whitelists and state
        self.whitelists: Dict[int, Set[int]] = {}
        self.lockdown: Dict[int, bool] = {}
        self.panic: Dict[int, bool] = {}
        self.bot_baseline: Dict[int, Tuple[int, int]] = {}
        self.executor_cache: Dict[int, Dict[str, Tuple[int, float]]] = {}
        self.trusted_users: Dict[int, Set[int]] = {}
        self.false_positives: Dict[int, List[Tuple[int, float, str]]] = {}
        
        # Stats
        self.stats: Dict[int, Dict[str, int]] = {}
    
    def init_guild(self, guild_id: int):
        """Initialize guild state."""
        for attr in ['events', 'guild_events', 'scores', 'distributed_events',
                     'attack_fingerprints', 'slow_nuke_counters', 'shadow_queue',
                     'silent_restrictions', 'backups', 'backup_hashes', 'permission_chain',
                     'intent_history', 'staging_signals', 'rate_limit_state',
                     'audit_log_sequence', 'whitelists', 'executor_cache',
                     'trusted_users', 'false_positives']:
            getattr(self, attr).setdefault(guild_id, {} if attr not in ['guild_events', 'audit_log_sequence', 'whitelists', 'trusted_users'] else (deque(maxlen=1000) if attr in ['guild_events', 'audit_log_sequence'] else set()))
        
        self.lockdown.setdefault(guild_id, False)
        self.panic.setdefault(guild_id, False)
        self.audit_log_anomalies.setdefault(guild_id, 0)
        
        if guild_id not in self.stats:
            self.stats[guild_id] = {
                "threats_detected": 0,
                "threats_mitigated": 0,
                "attacks_prevented": 0,
                "distributed_attacks": 0,
                "slow_nukes": 0,
                "shadow_actions": 0,
                "staging_detected": 0,
            }

STATE = DefensiveState()
BOT_USER_ID: Optional[int] = None
bot = commands.Bot(command_prefix="!", intents=discord.Intents.all())

# ============================================================================
# MULTI-EXECUTOR CORRELATION
# ============================================================================

def detect_distributed_attack(guild_id: int, event_type: str) -> Tuple[bool, List[int]]:
    """
    Detect coordinated attack across multiple users.
    
    Returns: (is_distributed, user_ids_involved)
    """
    current = time.time()
    
    if guild_id not in STATE.distributed_events:
        STATE.distributed_events[guild_id] = {}
    
    if event_type not in STATE.distributed_events[guild_id]:
        STATE.distributed_events[guild_id][event_type] = []
    
    # Get recent events
    recent = [
        (t, uid) for t, uid in STATE.distributed_events[guild_id][event_type]
        if current - t <= DISTRIBUTED_ATTACK_WINDOW
    ]
    
    # Count unique users
    unique_users = set(uid for _, uid in recent)
    
    # Check threshold
    if len(recent) >= GUILD_BURST_THRESHOLD and len(unique_users) >= 2:
        logger.critical(
            f"[Guild {guild_id}] DISTRIBUTED ATTACK: {len(recent)} {event_type} "
            f"by {len(unique_users)} users"
        )
        return True, list(unique_users)
    
    return False, []

def track_guild_event(guild_id: int, event_type: str, user_id: int):
    """Track event at guild level for correlation."""
    current = time.time()
    
    if guild_id not in STATE.distributed_events:
        STATE.distributed_events[guild_id] = {}
    
    if event_type not in STATE.distributed_events[guild_id]:
        STATE.distributed_events[guild_id][event_type] = []
    
    STATE.distributed_events[guild_id][event_type].append((current, user_id))
    
    # Keep only recent
    STATE.distributed_events[guild_id][event_type] = [
        (t, uid) for t, uid in STATE.distributed_events[guild_id][event_type]
        if current - t <= DISTRIBUTED_ATTACK_WINDOW * 2
    ]

# ============================================================================
# ATTACK FINGERPRINTING
# ============================================================================

def generate_fingerprint(events: List[Tuple[float, str, int]]) -> str:
    """
    Generate attack fingerprint from event sequence.
    
    Captures:
    - Event types in order
    - Timing deltas
    - User distribution
    """
    if len(events) < 2:
        return ""
    
    pattern = []
    for i in range(len(events)):
        event_type = events[i][1]
        
        if i > 0:
            delta = int((events[i][0] - events[i-1][0]) * 1000)
            pattern.append(f"{event_type}:{delta}")
        else:
            pattern.append(event_type)
    
    pattern_str = "|".join(pattern)
    return hashlib.md5(pattern_str.encode()).hexdigest()[:12]

def match_fingerprint(fp1: str, fp2: str) -> float:
    """Calculate fingerprint similarity."""
    if not fp1 or not fp2:
        return 0.0
    
    matches = sum(1 for a, b in zip(fp1, fp2) if a == b)
    return matches / max(len(fp1), len(fp2))

def detect_known_tool(guild_id: int, fingerprint: str) -> Optional[str]:
    """Check if fingerprint matches known attack tool."""
    for stored_fp, stored_time in STATE.attack_fingerprints.get(guild_id, []):
        similarity = match_fingerprint(fingerprint, stored_fp)
        
        if similarity >= FINGERPRINT_MATCH_THRESHOLD:
            return stored_fp
    
    return None

def register_attack_fingerprint(guild_id: int, fingerprint: str):
    """Register new attack fingerprint."""
    if guild_id not in STATE.attack_fingerprints:
        STATE.attack_fingerprints[guild_id] = []
    
    STATE.attack_fingerprints[guild_id].append((fingerprint, time.time()))
    
    # Keep only recent
    cutoff = time.time() - 3600  # 1 hour
    STATE.attack_fingerprints[guild_id] = [
        (fp, t) for fp, t in STATE.attack_fingerprints[guild_id]
        if t > cutoff
    ]

# ============================================================================
# SLOW NUKE DETECTION
# ============================================================================

def detect_slow_nuke(guild_id: int, user_id: int, event_type: str) -> bool:
    """
    Detect slow, persistent nuke attempts.
    
    Checks multiple time windows for accumulated actions.
    """
    current = time.time()
    
    if guild_id not in STATE.slow_nuke_counters:
        STATE.slow_nuke_counters[guild_id] = {}
    
    if user_id not in STATE.slow_nuke_counters[guild_id]:
        STATE.slow_nuke_counters[guild_id][user_id] = {}
    
    # Check each window
    for window in SLOW_NUKE_WINDOWS:
        if window not in STATE.slow_nuke_counters[guild_id][user_id]:
            STATE.slow_nuke_counters[guild_id][user_id][window] = 0
        
        # Increment counter
        STATE.slow_nuke_counters[guild_id][user_id][window] += 1
        
        # Check threshold
        threshold = SLOW_NUKE_THRESHOLDS.get(window, {}).get(event_type, 999)
        count = STATE.slow_nuke_counters[guild_id][user_id][window]
        
        if count >= threshold:
            logger.critical(
                f"[Guild {guild_id}] SLOW NUKE: {count} {event_type} "
                f"in {window}s by user {user_id}"
            )
            return True
    
    return False

def cleanup_slow_nuke_counters(guild_id: int):
    """Cleanup old counters (background task)."""
    current = time.time()
    
    if guild_id not in STATE.slow_nuke_counters:
        return
    
    for user_id in list(STATE.slow_nuke_counters[guild_id].keys()):
        for window in SLOW_NUKE_WINDOWS:
            if window in STATE.slow_nuke_counters[guild_id][user_id]:
                # Decay counter
                STATE.slow_nuke_counters[guild_id][user_id][window] = int(
                    STATE.slow_nuke_counters[guild_id][user_id][window] * 0.9
                )

# ============================================================================
# SHADOW MITIGATION
# ============================================================================

async def shadow_restrict_user(guild: discord.Guild, user_id: int, action: str):
    """
    Apply invisible restrictions without ban.
    
    Actions:
    - Remove dangerous permissions
    - Move to lower role
    - Apply internal rate limits
    """
    guild_id = guild.id
    
    if guild_id not in STATE.silent_restrictions:
        STATE.silent_restrictions[guild_id] = {}
    
    if user_id not in STATE.silent_restrictions[guild_id]:
        STATE.silent_restrictions[guild_id][user_id] = set()
    
    STATE.silent_restrictions[guild_id][user_id].add(action)
    
    member = guild.get_member(user_id)
    if not member:
        return
    
    logger.info(f"[{guild.name}] Shadow restricting user {user_id} for {action}")
    
    # Find roles with dangerous permissions
    dangerous_roles = []
    for role in member.roles:
        if any(perm for perm, value in role.permissions if value and perm in 
               ["administrator", "manage_guild", "manage_roles", "manage_channels"]):
            dangerous_roles.append(role)
    
    # Remove dangerous roles silently
    if dangerous_roles:
        try:
            await member.remove_roles(*dangerous_roles, reason="Shadow restriction")
            STATE.stats[guild_id]["shadow_actions"] += 1
        except:
            pass

def queue_shadow_action(guild_id: int, user_id: int, action: str):
    """Queue shadow action with random delay."""
    if guild_id not in STATE.shadow_queue:
        STATE.shadow_queue[guild_id] = []
    
    delay = random.uniform(SHADOW_MODE_DELAY_MIN, SHADOW_MODE_DELAY_MAX)
    execute_time = time.time() + delay
    
    STATE.shadow_queue[guild_id].append((user_id, action, execute_time))

# ============================================================================
# TRANSACTIONAL ROLLBACK
# ============================================================================

async def create_snapshot(guild: discord.Guild) -> Dict:
    """Create complete snapshot with verification."""
    logger.info(f"[{guild.name}] Creating transactional snapshot...")
    
    snapshot = {
        "timestamp": time.time(),
        "guild_id": guild.id,
        "guild_name": guild.name,
        "roles": [],
        "categories": [],
        "channels": [],
        "phase": "complete"
    }
    
    # Phase 1: Roles with full data
    for role in guild.roles:
        if not role.is_default() and not role.managed:
            snapshot["roles"].append({
                "id": role.id,
                "name": role.name,
                "permissions": role.permissions.value,
                "color": role.color.value,
                "hoist": role.hoist,
                "mentionable": role.mentionable,
                "position": role.position,
            })
    
    # Phase 2: Categories
    for category in guild.categories:
        snapshot["categories"].append({
            "id": category.id,
            "name": category.name,
            "position": category.position,
        })
    
    # Phase 3: Channels with overwrites
    for channel in guild.channels:
        if isinstance(channel, discord.CategoryChannel):
            continue
        
        ch_data = {
            "id": channel.id,
            "name": channel.name,
            "type": str(channel.type),
            "position": channel.position,
            "category_id": channel.category_id if hasattr(channel, 'category_id') else None,
        }
        
        if isinstance(channel, discord.TextChannel):
            ch_data.update({
                "topic": channel.topic,
                "slowmode": channel.slowmode_delay,
                "nsfw": channel.nsfw,
            })
        elif isinstance(channel, discord.VoiceChannel):
            ch_data.update({
                "bitrate": channel.bitrate,
                "user_limit": channel.user_limit,
            })
        
        snapshot["channels"].append(ch_data)
    
    # Compute hash
    snapshot_str = json.dumps(snapshot, sort_keys=True)
    snapshot_hash = hashlib.sha256(snapshot_str.encode()).hexdigest()[:16]
    
    # Store with hash
    guild_id = guild.id
    if guild_id not in STATE.backups:
        STATE.backups[guild_id] = []
        STATE.backup_hashes[guild_id] = []
    
    STATE.backups[guild_id].append(snapshot)
    STATE.backup_hashes[guild_id].append(snapshot_hash)
    
    # Keep last 10
    if len(STATE.backups[guild_id]) > 10:
        STATE.backups[guild_id] = STATE.backups[guild_id][-10:]
        STATE.backup_hashes[guild_id] = STATE.backup_hashes[guild_id][-10:]
    
    logger.info(f"[{guild.name}] Snapshot complete. Hash: {snapshot_hash}")
    
    return snapshot

async def transactional_restore(guild: discord.Guild) -> Dict[str, int]:
    """Restore with phases and verification."""
    guild_id = guild.id
    
    if not STATE.backups.get(guild_id):
        logger.error(f"[{guild.name}] No snapshots available")
        return {"error": 1}
    
    snapshot = STATE.backups[guild_id][-1]
    expected_hash = STATE.backup_hashes[guild_id][-1]
    
    # Verify integrity
    snapshot_str = json.dumps(snapshot, sort_keys=True)
    actual_hash = hashlib.sha256(snapshot_str.encode()).hexdigest()[:16]
    
    if actual_hash != expected_hash:
        logger.error(f"[{guild.name}] Snapshot integrity check FAILED")
        return {"error": 1, "reason": "integrity_check_failed"}
    
    logger.critical(f"[{guild.name}] Starting transactional restore...")
    
    stats = {"roles": 0, "categories": 0, "channels": 0, "errors": 0}
    
    # Phase 1: Roles
    try:
        existing = {r.name for r in guild.roles}
        for role_data in sorted(snapshot["roles"], key=lambda x: -x["position"]):
            if role_data["name"] not in existing:
                try:
                    await guild.create_role(
                        name=role_data["name"],
                        permissions=discord.Permissions(role_data["permissions"]),
                        color=discord.Color(role_data["color"]),
                        hoist=role_data["hoist"],
                        mentionable=role_data["mentionable"],
                        reason="Transactional restore"
                    )
                    stats["roles"] += 1
                    await asyncio.sleep(0.15)
                except Exception as e:
                    logger.error(f"Role restore error: {e}")
                    stats["errors"] += 1
    except Exception as e:
        logger.error(f"Phase 1 (roles) failed: {e}")
        return {"error": 1, "phase": "roles"}
    
    # Phase 2: Categories
    try:
        existing = {c.name for c in guild.categories}
        for cat_data in snapshot["categories"]:
            if cat_data["name"] not in existing:
                try:
                    await guild.create_category(
                        cat_data["name"],
                        position=cat_data["position"],
                        reason="Transactional restore"
                    )
                    stats["categories"] += 1
                    await asyncio.sleep(0.15)
                except Exception as e:
                    logger.error(f"Category restore error: {e}")
                    stats["errors"] += 1
    except Exception as e:
        logger.error(f"Phase 2 (categories) failed: {e}")
        return {"error": 1, "phase": "categories"}
    
    # Phase 3: Channels
    try:
        existing = {ch.name for ch in guild.channels}
        for ch_data in snapshot["channels"]:
            if ch_data["name"] not in existing:
                try:
                    if "text" in ch_data["type"].lower():
                        await guild.create_text_channel(
                            ch_data["name"],
                            topic=ch_data.get("topic"),
                            slowmode_delay=ch_data.get("slowmode", 0),
                            nsfw=ch_data.get("nsfw", False),
                            reason="Transactional restore"
                        )
                    elif "voice" in ch_data["type"].lower():
                        await guild.create_voice_channel(
                            ch_data["name"],
                            bitrate=min(ch_data.get("bitrate", 64000), guild.bitrate_limit),
                            user_limit=ch_data.get("user_limit", 0),
                            reason="Transactional restore"
                        )
                    stats["channels"] += 1
                    await asyncio.sleep(0.2)
                except Exception as e:
                    logger.error(f"Channel restore error: {e}")
                    stats["errors"] += 1
    except Exception as e:
        logger.error(f"Phase 3 (channels) failed: {e}")
        return {"error": 1, "phase": "channels"}
    
    logger.critical(
        f"[{guild.name}] Restore complete: "
        f"{stats['roles']} roles, {stats['categories']} cats, {stats['channels']} chs"
    )
    
    return stats

# ============================================================================
# TRUST CHAIN TRACKING
# ============================================================================

def track_permission_grant(guild_id: int, granter_id: int, receiver_id: int):
    """Track who gave permissions to whom."""
    current = time.time()
    
    if guild_id not in STATE.permission_chain:
        STATE.permission_chain[guild_id] = {}
    
    if receiver_id not in STATE.permission_chain[guild_id]:
        STATE.permission_chain[guild_id][receiver_id] = []
    
    STATE.permission_chain[guild_id][receiver_id].append((granter_id, current))

def get_trust_chain(guild_id: int, user_id: int) -> List[int]:
    """Get complete trust chain for user."""
    if guild_id not in STATE.permission_chain:
        return []
    
    if user_id not in STATE.permission_chain[guild_id]:
        return []
    
    chain = []
    for granter_id, timestamp in STATE.permission_chain[guild_id][user_id]:
        if time.time() - timestamp <= 3600:  # Last hour
            chain.append(granter_id)
    
    return chain

async def ban_trust_chain(guild: discord.Guild, attacker_id: int):
    """Ban entire trust chain (accomplices)."""
    chain = get_trust_chain(guild.id, attacker_id)
    
    if not chain:
        return
    
    logger.warning(f"[{guild.name}] Banning trust chain: {len(chain)} accomplices")
    
    for user_id in chain:
        if user_id == attacker_id:
            continue
        
        member = guild.get_member(user_id)
        if member and member.id != guild.owner_id:
            try:
                await guild.ban(member, reason="Trust chain: Accomplice to attack")
            except:
                pass

# ============================================================================
# ANTI-AUDIT-LOG POISONING
# ============================================================================

def verify_audit_log_integrity(guild_id: int, entry) -> bool:
    """Verify audit log entry is legitimate."""
    current = time.time()
    
    if guild_id not in STATE.audit_log_sequence:
        STATE.audit_log_sequence[guild_id] = deque(maxlen=100)
    
    # Check timing
    if STATE.audit_log_sequence[guild_id]:
        last_entry_time = STATE.audit_log_sequence[guild_id][-1]
        
        # Too fast (spam)
        if current - last_entry_time < 0.001:
            STATE.audit_log_anomalies[guild_id] = STATE.audit_log_anomalies.get(guild_id, 0) + 1
            
            if STATE.audit_log_anomalies[guild_id] >= 5:
                logger.warning(f"[Guild {guild_id}] Audit log poisoning detected")
                return False
    
    STATE.audit_log_sequence[guild_id].append(current)
    
    return True

# ============================================================================
# LONG-TERM INTENT MODELING
# ============================================================================

def update_long_term_intent(guild_id: int, user_id: int, severity: float):
    """Update long-term intent score."""
    current = time.time()
    
    if guild_id not in STATE.intent_history:
        STATE.intent_history[guild_id] = {}
    
    if user_id not in STATE.intent_history[guild_id]:
        STATE.intent_history[guild_id][user_id] = []
    
    STATE.intent_history[guild_id][user_id].append((current, severity))
    
    # Keep last 24 hours
    cutoff = current - (INTENT_DECAY_HOURS * 3600)
    STATE.intent_history[guild_id][user_id] = [
        (t, s) for t, s in STATE.intent_history[guild_id][user_id]
        if t > cutoff
    ]

def calculate_accumulated_intent(guild_id: int, user_id: int) -> float:
    """Calculate accumulated intent score over time."""
    if guild_id not in STATE.intent_history:
        return 0.0
    
    if user_id not in STATE.intent_history[guild_id]:
        return 0.0
    
    current = time.time()
    total_intent = 0.0
    
    for timestamp, severity in STATE.intent_history[guild_id][user_id]:
        age_hours = (current - timestamp) / 3600
        decay = 0.9 ** age_hours  # Slow decay
        total_intent += severity * decay
    
    return total_intent

# ============================================================================
# PRE-NUKE STAGING DETECTION
# ============================================================================

def detect_staging(guild_id: int, user_id: int, signal: str):
    """Detect pre-nuke staging indicators."""
    current = time.time()
    
    if guild_id not in STATE.staging_signals:
        STATE.staging_signals[guild_id] = {}
    
    if user_id not in STATE.staging_signals[guild_id]:
        STATE.staging_signals[guild_id][user_id] = []
    
    STATE.staging_signals[guild_id][user_id].append((current, signal))
    
    # Check for multiple signals
    recent = [
        s for t, s in STATE.staging_signals[guild_id][user_id]
        if current - t <= 300  # 5 minutes
    ]
    
    if len(recent) >= 3:
        logger.warning(
            f"[Guild {guild_id}] STAGING DETECTED: User {user_id} "
            f"has {len(recent)} indicators"
        )
        return True
    
    return False

# ============================================================================
# INTERNAL RATE LIMITING
# ============================================================================

def check_internal_rate_limit(guild_id: int, user_id: int, action: str) -> bool:
    """Check if user exceeds internal rate limit."""
    if action not in INTERNAL_RATE_LIMITS:
        return False
    
    max_actions, window = INTERNAL_RATE_LIMITS[action]
    current = time.time()
    
    if guild_id not in STATE.rate_limit_state:
        STATE.rate_limit_state[guild_id] = {}
    
    if user_id not in STATE.rate_limit_state[guild_id]:
        STATE.rate_limit_state[guild_id][user_id] = {}
    
    if action not in STATE.rate_limit_state[guild_id][user_id]:
        STATE.rate_limit_state[guild_id][user_id][action] = deque(maxlen=100)
    
    # Track action
    STATE.rate_limit_state[guild_id][user_id][action].append(current)
    
    # Count recent
    recent = [
        t for t in STATE.rate_limit_state[guild_id][user_id][action]
        if current - t <= window
    ]
    
    if len(recent) > max_actions:
        logger.info(
            f"[Guild {guild_id}] Rate limit exceeded: User {user_id} "
            f"did {len(recent)} {action} in {window}s"
        )
        return True
    
    return False

# ============================================================================
# PROBABILISTIC DECISIONS
# ============================================================================

def apply_jitter(threshold: float) -> float:
    """Apply random jitter to threshold."""
    if not JITTER_ENABLED:
        return threshold
    
    variation = threshold * JITTER_RANGE
    return threshold + random.uniform(-variation, variation)

def should_act_probabilistic(base_probability: float) -> bool:
    """Make probabilistic decision."""
    if not JITTER_ENABLED:
        return base_probability >= 0.5
    
    # Add randomness
    adjusted = base_probability + random.uniform(-0.1, 0.1)
    return random.random() < adjusted

# ============================================================================
# CORE DETECTION (CONSOLIDATED)
# ============================================================================

def detect_burst_sync(guild_id: int, event_type: str, user_id: int) -> Tuple[bool, int]:
    """Synchronous burst detection."""
    timestamp = time.time()
    
    # Track event
    if guild_id not in STATE.events:
        STATE.events[guild_id] = {}
    
    if event_type not in STATE.events[guild_id]:
        STATE.events[guild_id][event_type] = deque(maxlen=1000)
    
    STATE.events[guild_id][event_type].append((timestamp, user_id))
    
    # Get recent from this user
    window = 0.5
    recent = [
        t for t, uid in STATE.events[guild_id][event_type]
        if timestamp - t <= window and uid == user_id
    ]
    
    count = len(recent)
    threshold = apply_jitter(THRESHOLDS.get(event_type, 5))
    
    return count >= threshold, count

def is_whitelisted(guild_id: int, user_id: int) -> bool:
    """Check whitelist."""
    if user_id == BOT_USER_ID:
        return True
    
    return user_id in STATE.whitelists.get(guild_id, set())

def is_trusted(guild_id: int, user_id: int) -> bool:
    """Check if trusted (learned from false positives)."""
    return user_id in STATE.trusted_users.get(guild_id, set())

# ============================================================================
# MITIGATION
# ============================================================================

async def execute_ban(guild: discord.Guild, user_id: int, reason: str) -> bool:
    """Execute ban with timeout."""
    member = guild.get_member(user_id)
    if not member or member.id == guild.owner_id:
        return False
    
    if is_whitelisted(guild.id, user_id):
        return False
    
    # Probabilistic delay
    if JITTER_ENABLED and random.random() < 0.2:
        await asyncio.sleep(random.uniform(0.5, 2.0))
    
    try:
        await asyncio.wait_for(
            guild.ban(member, reason=f"Security: {reason}", delete_message_seconds=0),
            timeout=0.03
        )
        
        STATE.stats[guild.id]["threats_mitigated"] += 1
        logger.critical(f"[{guild.name}] BANNED: {member} - {reason}")
        return True
        
    except:
        return False

async def emergency_lockdown(guild: discord.Guild, reason: str):
    """Emergency lockdown."""
    guild_id = guild.id
    
    if STATE.lockdown[guild_id]:
        return
    
    STATE.lockdown[guild_id] = True
    STATE.panic[guild_id] = True
    
    logger.critical(f"[{guild.name}] LOCKDOWN: {reason}")
    
    for channel in guild.text_channels[:50]:
        try:
            await channel.set_permissions(
                guild.default_role,
                send_messages=False,
                reason=f"Lockdown: {reason}"
            )
        except:
            pass

# ============================================================================
# EVENT HANDLERS
# ============================================================================

@bot.event
async def on_ready():
    """Bot ready."""
    global BOT_USER_ID
    BOT_USER_ID = bot.user.id
    
    logger.info("=" * 60)
    logger.info("DEFINITIVE ANTI-NUKE BOT - COMPLETE EDITION")
    logger.info(f"Bot: {bot.user.name} (ID: {bot.user.id})")
    logger.info(f"Guilds: {len(bot.guilds)}")
    logger.info("Multi-executor correlation: ENABLED")
    logger.info("Attack fingerprinting: ENABLED")
    logger.info("Slow nuke detection: ENABLED")
    logger.info("Shadow mitigation: ENABLED")
    logger.info("Transactional restore: ENABLED")
    logger.info("=" * 60)
    
    try:
        synced = await bot.tree.sync()
        logger.info(f"Synced {len(synced)} commands")
    except Exception as e:
        logger.error(f"Sync failed: {e}")
    
    # Start tasks
    if not snapshot_task.is_running():
        snapshot_task.start()
    
    if not shadow_processor.is_running():
        shadow_processor.start()
    
    if not cleanup_task.is_running():
        cleanup_task.start()
    
    # Initialize guilds
    for guild in bot.guilds:
        STATE.init_guild(guild.id)
        asyncio.create_task(create_snapshot(guild))

@bot.event
async def on_guild_channel_delete(channel: discord.abc.GuildChannel):
    """Channel delete - complete detection."""
    detection_start = time.time()
    
    guild = channel.guild
    guild_id = guild.id
    
    # Get executor
    executor_id = STATE.executor_cache.get(guild_id, {}).get("channel_delete", (None, 0))[0]
    
    if not executor_id or time.time() - STATE.executor_cache.get(guild_id, {}).get("channel_delete", (0, 0))[1] > 2:
        try:
            async for entry in guild.audit_logs(limit=3, action=AuditLogAction.channel_delete):
                if entry.target.id == channel.id:
                    if verify_audit_log_integrity(guild_id, entry):
                        executor_id = entry.user.id
                        if guild_id not in STATE.executor_cache:
                            STATE.executor_cache[guild_id] = {}
                        STATE.executor_cache[guild_id]["channel_delete"] = (executor_id, time.time())
                    break
        except:
            pass
    
    if not executor_id or executor_id == BOT_USER_ID:
        return
    
    # Track guild-level
    track_guild_event(guild_id, "channel_delete", executor_id)
    
    # Multi-executor detection
    is_distributed, attackers = detect_distributed_attack(guild_id, "channel_delete")
    
    if is_distributed:
        logger.critical(f"[{guild.name}] DISTRIBUTED ATTACK: {len(attackers)} users")
        
        STATE.stats[guild_id]["distributed_attacks"] += 1
        
        # Ban all
        if should_act_probabilistic(0.9):
            for attacker_id in attackers:
                await execute_ban(guild, attacker_id, "Distributed attack")
                await ban_trust_chain(guild, attacker_id)
        
        await emergency_lockdown(guild, "Distributed attack")
        await transactional_restore(guild)
        return
    
    # Fingerprinting
    recent_events = [
        (t, "channel_delete", uid) 
        for t, uid in STATE.distributed_events.get(guild_id, {}).get("channel_delete", [])
        if time.time() - t <= FINGERPRINT_WINDOW
    ]
    
    if len(recent_events) >= 3:
        fingerprint = generate_fingerprint(recent_events)
        known_tool = detect_known_tool(guild_id, fingerprint)
        
        if known_tool:
            logger.critical(f"[{guild.name}] KNOWN TOOL DETECTED: {fingerprint}")
            if should_act_probabilistic(0.95):
                await execute_ban(guild, executor_id, f"Known tool: {fingerprint}")
                await emergency_lockdown(guild, "Known tool detected")
                await transactional_restore(guild)
                return
        else:
            register_attack_fingerprint(guild_id, fingerprint)
    
    # Slow nuke detection
    if detect_slow_nuke(guild_id, executor_id, "channel_delete"):
        logger.critical(f"[{guild.name}] SLOW NUKE: User {executor_id}")
        
        STATE.stats[guild_id]["slow_nukes"] += 1
        
        if SHADOW_MODE_ENABLED:
            queue_shadow_action(guild_id, executor_id, "slow_nuke")
        else:
            await execute_ban(guild, executor_id, "Slow nuke")
        
        return
    
    # Internal rate limit
    if check_internal_rate_limit(guild_id, executor_id, "channel_delete"):
        logger.warning(f"[{guild.name}] Internal rate limit: User {executor_id}")
        
        if SHADOW_MODE_ENABLED:
            await shadow_restrict_user(guild, executor_id, "rate_limit")
        
        return
    
    # Burst detection
    is_burst, count = detect_burst_sync(guild_id, "channel_delete", executor_id)
    
    if is_burst:
        logger.critical(f"[{guild.name}] BURST: {count} channel deletes")
        
        # Update long-term intent
        update_long_term_intent(guild_id, executor_id, 0.3)
        
        # Check accumulated intent
        accumulated = calculate_accumulated_intent(guild_id, executor_id)
        
        if accumulated >= INTENT_CRITICAL_THRESHOLD:
            logger.critical(f"[{guild.name}] CRITICAL INTENT: User {executor_id} ({accumulated:.2f})")
            
            await execute_ban(guild, executor_id, f"Critical intent: {accumulated:.2f}")
            await ban_trust_chain(guild, executor_id)
            await emergency_lockdown(guild, "Critical intent")
            await transactional_restore(guild)
        elif should_act_probabilistic(0.8):
            await execute_ban(guild, executor_id, f"Burst: {count}")
            await emergency_lockdown(guild, "Channel delete burst")
            await transactional_restore(guild)
        
        STATE.stats[guild_id]["attacks_prevented"] += 1
    
    # Performance check
    elapsed = (time.time() - detection_start) * 1000
    if elapsed > 15:
        logger.warning(f"Detection took {elapsed:.1f}ms")

@bot.event
async def on_guild_role_create(role: discord.Role):
    """Role create - staging detection."""
    guild = role.guild
    guild_id = guild.id
    
    # Get creator
    creator_id = None
    try:
        async for entry in guild.audit_logs(limit=3, action=AuditLogAction.role_create):
            if entry.target.id == role.id:
                creator_id = entry.user.id
                break
    except:
        pass
    
    if not creator_id or creator_id == BOT_USER_ID:
        return
    
    # Check for suspicious names
    suspicious = any(
        pattern in role.name.lower() 
        for pattern in STAGING_INDICATORS["suspicious_role_names"]
    )
    
    if suspicious:
        detect_staging(guild_id, creator_id, "suspicious_role_name")
    
    # Check bulk creation
    recent_creates = [
        t for t, uid in STATE.distributed_events.get(guild_id, {}).get("role_create", [])
        if time.time() - t <= 30 and uid == creator_id
    ]
    
    if len(recent_creates) >= STAGING_INDICATORS["bulk_role_create"]:
        if detect_staging(guild_id, creator_id, "bulk_role_create"):
            logger.warning(f"[{guild.name}] STAGING: Bulk role creation by {creator_id}")
            
            STATE.stats[guild_id]["staging_detected"] += 1
            
            if SHADOW_MODE_ENABLED:
                await shadow_restrict_user(guild, creator_id, "staging")

@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    """Member update - trust chain tracking."""
    guild = after.guild
    guild_id = guild.id
    
    # Check for new dangerous roles
    new_roles = set(after.roles) - set(before.roles)
    
    for role in new_roles:
        dangerous = any(
            perm for perm, value in role.permissions 
            if value and perm in ["administrator", "manage_guild", "manage_roles"]
        )
        
        if dangerous:
            # Find who granted
            try:
                async for entry in guild.audit_logs(limit=5, action=AuditLogAction.member_role_update):
                    if entry.target.id == after.id:
                        track_permission_grant(guild_id, entry.user.id, after.id)
                        break
            except:
                pass

# ============================================================================
# BACKGROUND TASKS
# ============================================================================

@tasks.loop(minutes=5)
async def snapshot_task():
    """Create snapshots."""
    for guild in bot.guilds:
        try:
            await create_snapshot(guild)
        except Exception as e:
            logger.error(f"Snapshot failed for {guild.name}: {e}")

@tasks.loop(seconds=10)
async def shadow_processor():
    """Process shadow action queue."""
    current = time.time()
    
    for guild in bot.guilds:
        guild_id = guild.id
        
        if guild_id not in STATE.shadow_queue:
            continue
        
        # Process due actions
        due_actions = [
            (uid, action, t) for uid, action, t in STATE.shadow_queue[guild_id]
            if t <= current
        ]
        
        for user_id, action, _ in due_actions:
            await shadow_restrict_user(guild, user_id, action)
        
        # Remove processed
        STATE.shadow_queue[guild_id] = [
            (uid, action, t) for uid, action, t in STATE.shadow_queue[guild_id]
            if t > current
        ]

@tasks.loop(minutes=10)
async def cleanup_task():
    """Cleanup old data."""
    for guild_id in list(STATE.slow_nuke_counters.keys()):
        cleanup_slow_nuke_counters(guild_id)

# ============================================================================
# COMMANDS
# ============================================================================

@bot.tree.command(name="security")
async def cmd_security(interaction: discord.Interaction):
    """Security status."""
    guild_id = interaction.guild_id
    
    if guild_id not in STATE.stats:
        STATE.init_guild(guild_id)
    
    stats = STATE.stats[guild_id]
    
    embed = discord.Embed(
        title=f"Security Status - {interaction.guild.name}",
        color=discord.Color.green() if not STATE.lockdown[guild_id] else discord.Color.red()
    )
    
    status = "LOCKDOWN" if STATE.lockdown[guild_id] else "OPERATIONAL"
    embed.add_field(name="Status", value=status, inline=False)
    
    embed.add_field(name="Threats Detected", value=f"`{stats['threats_detected']}`", inline=True)
    embed.add_field(name="Threats Mitigated", value=f"`{stats['threats_mitigated']}`", inline=True)
    embed.add_field(name="Attacks Prevented", value=f"`{stats['attacks_prevented']}`", inline=True)
    embed.add_field(name="Distributed Attacks", value=f"`{stats['distributed_attacks']}`", inline=True)
    embed.add_field(name="Slow Nukes", value=f"`{stats['slow_nukes']}`", inline=True)
    embed.add_field(name="Shadow Actions", value=f"`{stats['shadow_actions']}`", inline=True)
    embed.add_field(name="Staging Detected", value=f"`{stats['staging_detected']}`", inline=True)
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="whitelist")
async def cmd_whitelist(interaction: discord.Interaction, user: discord.User):
    """Add to whitelist."""
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("Admin only", ephemeral=True)
        return
    
    guild_id = interaction.guild_id
    if guild_id not in STATE.whitelists:
        STATE.whitelists[guild_id] = set()
    
    STATE.whitelists[guild_id].add(user.id)
    await interaction.response.send_message(f"{user.mention} whitelisted", ephemeral=True)

@bot.tree.command(name="snapshot")
async def cmd_snapshot(interaction: discord.Interaction):
    """Create snapshot."""
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("Admin only", ephemeral=True)
        return
    
    await interaction.response.defer(ephemeral=True)
    await create_snapshot(interaction.guild)
    await interaction.followup.send("Snapshot created", ephemeral=True)

@bot.tree.command(name="restore")
async def cmd_restore(interaction: discord.Interaction):
    """Restore from snapshot."""
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("Admin only", ephemeral=True)
        return
    
    await interaction.response.defer(ephemeral=True)
    await transactional_restore(interaction.guild)
    await interaction.followup.send("Restore complete", ephemeral=True)

@bot.tree.command(name="trustchain")
async def cmd_trust_chain(interaction: discord.Interaction, user: discord.User):
    """View trust chain."""
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("Admin only", ephemeral=True)
        return
    
    chain = get_trust_chain(interaction.guild_id, user.id)
    
    if not chain:
        await interaction.response.send_message(f"No trust chain for {user.mention}", ephemeral=True)
        return
    
    chain_str = ", ".join([f"<@{uid}>" for uid in chain])
    await interaction.response.send_message(
        f"Trust chain for {user.mention}: {chain_str}",
        ephemeral=True
    )

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    if not TOKEN:
        logger.error("TOKEN not set")
    else:
        bot.run(TOKEN, log_handler=None)
